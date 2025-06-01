/* Copyright 2022-2023 John "topjohnwu" Wu
 * Copyright 2024 The NoHello Contributors
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

#include <cstdlib>
#include <unistd.h>
#include <fcntl.h>
#include <android/log.h>
#include <filesystem>
#include <ranges>
#include <vector>
#include <utility> // For std::pair, std::move

#include "zygisk.hpp"
#include "external/android_filesystem_config.h"
#include "mountsinfo.cpp"
#include "utils.cpp"
#include "external/fdutils/fd_utils.cpp"
#include <sys/mount.h>
#include <sys/ptrace.h>
#include <endian.h>
#include <thread>
#include "log.h"
#include "PropertyManager.cpp"
#include "MountRuleParser.cpp"
#include "external/emoji.h"

using zygisk::Api;
using zygisk::AppSpecializeArgs;
using zygisk::ServerSpecializeArgs;

namespace fs = std::filesystem;

static constexpr off_t EXT_SUPERBLOCK_OFFSET = 0x400;
static constexpr off_t EXT_MAGIC_OFFSET = 0x38;
static constexpr off_t EXT_ERRORS_OFFSET = 0x3C;
static constexpr uint16_t EXT_MAGIC = 0xEF53;
static const std::vector<std::string> defaultRules = {
		R"(source { "KSU", "APatch", "magisk", "worker" } fs { "tmpfs" "overlay" })"
};

enum Advice {
	NORMAL = 0,
	MODULE_CONFLICT = 2,
};

enum State {
	SUCCESS = 0,
	FAILURE = 1
};

static const std::set<std::string> toumount_sources = {"KSU", "APatch", "magisk", "worker"};
static const std::string adbPathPrefix = "/data/adb";

static bool anomaly(MountRootResolver mrs, const MountInfo &mount) {
	const std::string resolved_root = mrs.resolveRoot(mount);
	if (resolved_root.starts_with(adbPathPrefix) || mount.getMountPoint().starts_with(adbPathPrefix)) {
		return true;
	}
	const auto& fs_type = mount.getFsType();
	const auto& mnt_src = mount.getMountSource();
	if (toumount_sources.count(mnt_src)) {
		return true;
	}
	if (fs_type == "overlay") {
		if (toumount_sources.count(mnt_src)) {
			return true;
		}
		const auto& fm = mount.getMountOptions().flagmap;
		if (fm.count("lowerdir") && fm.at("lowerdir").starts_with(adbPathPrefix)) {
			return true;
		}
		if (fm.count("upperdir") && fm.at("upperdir").starts_with(adbPathPrefix)) {
			return true;
		}
		if (fm.count("workdir") && fm.at("workdir").starts_with(adbPathPrefix)) {
			return true;
		}
	} else if (fs_type == "tmpfs") {
		if (toumount_sources.count(mnt_src)) {
			return true;
		}
	}
	return false;
}

static bool anomaly(const MountRuleParser::MountRule& rule, MountRootResolver mrs, const MountInfo &mount) {
	const std::string resolvedRoot = mrs.resolveRoot(mount);
	const auto& fsType = mount.getFsType();
	if (fsType != "overlay") {
		return rule.matches(resolvedRoot, mount.getMountPoint(), fsType, mount.getMountSource());
	} else {
		const auto& fm = mount.getMountOptions().flagmap;
		std::vector<std::string> roots = {resolvedRoot};
		for (const auto* key : {"lowerdir", "upperdir", "workdir"}) {
			auto it = fm.find(key);
			if (it != fm.end()) {
				roots.push_back(it->second);
			}
		}
		return rule.matches(roots, mount.getMountPoint(), fsType, mount.getMountSource());
	}
	return false;
}

static bool anomaly(const std::vector<MountRuleParser::MountRule>& rules, MountRootResolver mrs, const MountInfo &mount) {
	const std::string resolvedRoot = mrs.resolveRoot(mount);
	const auto& fsType = mount.getFsType();
	const auto& fm = mount.getMountOptions().flagmap;
	for (const auto& rule : rules) {
		if (fsType != "overlay") {
			if (rule.matches(resolvedRoot, mount.getMountPoint(), fsType, mount.getMountSource()))
				return true;
		} else {
			std::vector<std::string> roots = {resolvedRoot};
			for (const auto* key : {"lowerdir", "upperdir", "workdir"}) {
				auto it = fm.find(key);
				if (it != fm.end()) {
					roots.push_back(it->second);
				}
			}
			if (rule.matches(roots, mount.getMountPoint(), fsType, mount.getMountSource()))
				return true;
		}
	}
	return false;
}

static std::pair<bool, bool> anomaly(const std::unique_ptr<FileDescriptorInfo> fdi) {
	if (fdi->is_sock) {
		std::string socket_name;
		if (fdi->GetSocketName(&socket_name)) {
			if (socket_name.find("magisk") != std::string::npos ||
				socket_name.find("kernelsu") != std::string::npos || // For KernelSU daemon, common pattern
				socket_name.find("ksud") != std::string::npos || // KernelSU daemon
				socket_name.find("apatchd") != std::string::npos || // For APatch daemon, common pattern
				socket_name.find("apd") != std::string::npos      // APatch daemon
					) {
				LOGD("Marking sensitive socket FD %d (%s) for sanitization.", fdi->fd, socket_name.c_str());
				return {true, true};
			}
		}
	} else { // Not a socket
		if (!fdi->file_path.starts_with("/memfd:") &&
			!fdi->file_path.starts_with("/dev/ashmem") && // Common, usually not root related
			!fdi->file_path.starts_with("[anon_inode:") && // e.g., [anon_inode:sync_fence]
			!fdi->file_path.empty() // Ensure path is not empty
				) {
			if (fdi->file_path.starts_with(adbPathPrefix) ||
				fdi->file_path.find("magisk") != std::string::npos ||
				fdi->file_path.find("kernelsu") != std::string::npos ||
				fdi->file_path.find("apatch") != std::string::npos) {
				LOGD("Marking sensitive file FD %d (%s) for sanitization.", fdi->fd, fdi->file_path.c_str());
				return {true, true};
			}
		}
	}
	return {false, false};
}


static std::unique_ptr<std::string> getExternalErrorBehaviour(const MountInfo& mount) {
	const auto& fs = mount.getFsType();
	if (fs != "ext2" && fs != "ext3" && fs != "ext4")
		return nullptr;
	std::ifstream mntsrc(mount.getMountSource(), std::ios::binary);
	if (!mntsrc || !mntsrc.is_open())
		return nullptr;
	uint16_t magic;
	mntsrc.seekg(EXT_SUPERBLOCK_OFFSET + EXT_MAGIC_OFFSET, std::ios::beg);
	mntsrc.read(reinterpret_cast<char *>(&magic), sizeof(magic));
	if (!mntsrc || mntsrc.gcount() != sizeof(magic))
		return nullptr;
	magic = le16toh(magic);
	if (magic != EXT_MAGIC)
		return nullptr;
	uint16_t errors;
	mntsrc.seekg(EXT_SUPERBLOCK_OFFSET + EXT_ERRORS_OFFSET, std::ios::beg);
	mntsrc.read(reinterpret_cast<char *>(&errors), sizeof(errors));
	if (!mntsrc || mntsrc.gcount() != sizeof(errors))
		return nullptr;
	errors = le16toh(errors);
	switch (errors)
	{
		case 1:
			return std::make_unique<std::string>("continue");
		case 2:
			return std::make_unique<std::string>("remount-ro");
		case 3:
			return std::make_unique<std::string>("panic");
		default:
			return nullptr;
	}
	return nullptr;
}

static void doumount(const std::string& mntPnt);

static void unmount(const std::vector<MountInfo>& mounts) {
	MountRootResolver mrs(mounts);
	for (const auto& mount : std::ranges::reverse_view(mounts)) {
		if (anomaly(mrs, mount))
			doumount(mount.getMountPoint());
	}
}

static void unmount(const std::vector<MountRuleParser::MountRule>& rules, const std::vector<MountInfo>& mounts) {
	MountRootResolver mrs(mounts);
	for (const auto& mount : std::ranges::reverse_view(mounts)) {
		if (anomaly(rules, mrs, mount))
			doumount(mount.getMountPoint());
	}
}

static void unmount(const MountRuleParser::MountRule& rule, const std::vector<MountInfo>& mounts) {
	MountRootResolver mrs(mounts);
	for (const auto& mount : std::ranges::reverse_view(mounts)) {
		if (anomaly(rule, mrs, mount))
			doumount(mount.getMountPoint());
	}
}

static void doumount(const std::string& mntPnt) {
	errno = 0;
	int res;
	const char *mntpnt = mntPnt.c_str();
	if ((res = umount2(mntpnt, MNT_DETACH)) == 0)
		LOGD("umount2(\"%s\", MNT_DETACH): returned (0): 0 (Success)", mntpnt);
	else
		LOGE("umount2(\"%s\", MNT_DETACH): returned %d: %d (%s)", mntpnt, res, errno, strerror(errno));
}

static void remount(const std::vector<MountInfo>& mounts) {
	for (const auto& mount : mounts) {
		if (mount.getMountPoint() == "/data") {
			const auto& mntopts = mount.getMountOptions();
			const auto& fm = mntopts.flagmap;
			if (!fm.count("errors"))
				break;
			auto errors = getExternalErrorBehaviour(mount);
			if (!errors || fm.at("errors") == *errors)
				break;
			auto mntflags = mount.getFlags();
			unsigned int flags = MS_REMOUNT;
			if (mntflags & MountFlags::NOSUID) {
				flags |= MS_NOSUID;
			}
			if (mntflags & MountFlags::NODEV) {
				flags |= MS_NODEV;
			}
			if (mntflags & MountFlags::NOEXEC) {
				flags |= MS_NOEXEC;
			}
			if (mntflags & MountFlags::NOATIME) {
				flags |= MS_NOATIME;
			}
			if (mntflags & MountFlags::NODIRATIME) {
				flags |= MS_NODIRATIME;
			}
			if (mntflags & MountFlags::RELATIME) {
				flags |= MS_RELATIME;
			}
			if (mntflags & MountFlags::NOSYMFOLLOW) {
				flags |= MS_NOSYMFOLLOW;
			}
			int res;
			if ((res = ::mount(nullptr, "/data", nullptr, flags, (std::string("errors=") + *errors).c_str())) == 0)
				LOGD("mount(nullptr, \"/data\", nullptr, 0x%x, \"errors=%s\"): returned 0: 0 (Success)", flags, errors->c_str());
			else
				LOGW("mount(NULL, \"/data\", NULL, 0x%x, \"errors=%s\"): returned %d: %d (%s)", flags, errors->c_str(), res, errno, strerror(errno));
			break;
		}
	}
}

int (*ar_unshare)(int) = nullptr;

static int reshare(int flags) {
	errno = 0;
	return flags == CLONE_NEWNS ? 0 : ar_unshare(flags & ~CLONE_NEWNS);
}

class NoHello : public zygisk::ModuleBase {
public:
    void onLoad(Api *_api, JNIEnv *_env) override {
        this->api = _api;
        this->env = _env;
    }

    void preAppSpecialize(AppSpecializeArgs *args) override {
        preSpecialize(args);
    }

	void postAppSpecialize(const AppSpecializeArgs *args) override {
		const char *process = env->GetStringUTFChars(args->nice_name, nullptr);
		postSpecialize(process);
		env->ReleaseStringUTFChars(args->nice_name, process);
	}

    void preServerSpecialize(ServerSpecializeArgs *args) override {
        //preSpecialize("system_server"); // System server usually doesn't need this level of hiding
		api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
    }

private:
    Api *api{};
    JNIEnv *env{};
	int cfd{};
	dev_t rundev{};
	ino_t runinode{};
	dev_t cdev{};
	ino_t cinode{};


    void preSpecialize(AppSpecializeArgs *args) {
		unsigned int flags = api->getFlags();
		const bool whitelist = access("/data/adb/nohello/whitelist", F_OK) == 0;
		const bool nodirtyro = access("/data/adb/nohello/no_dirtyro_ar", F_OK) == 0;
		if (flags & zygisk::StateFlag::PROCESS_GRANTED_ROOT) {
			api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
			return;
		}
		auto fn = [this](const std::string& lib) {
			auto di = devinoby(lib.c_str());
			if (di) {
				return *di;
			} else {
				LOGW("#[zygisk::?] devino[dl_iterate_phdr]: Failed to get device & inode for %s", lib.c_str());
				LOGI("#[zygisk::?] Fallback to use `/proc/self/maps`");
				return devinobymap(lib);
			}
		};
		if ((whitelist && isuserapp(args->uid)) || flags & zygisk::StateFlag::PROCESS_ON_DENYLIST) {
			pid_t pid = getpid(), ppid = getppid();
			cfd = api->connectCompanion(); // Companion FD
			api->exemptFd(cfd);
			if (write(cfd, &ppid, sizeof(ppid)) != sizeof(ppid)) {
				LOGE("#[zygisk::preSpecialize] write: [-> ppid]: %s", strerror(errno));
				close(cfd);
				api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
				return;
			}
			int advice;
			if (read(cfd, &advice, sizeof(advice)) != sizeof(advice)) {
				LOGE("#[zygisk::preSpecialize] read: [<- status]: %s", strerror(errno));
				close(cfd);
				api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
				return;
			}
			if (advice == MODULE_CONFLICT) {
				close(cfd);
				api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
				return;
			}
			std::tie(cdev, cinode) = fn("libc.so");
			if (!cdev && !cinode) {
				LOGE("#[zygisk::preSpecialize] Failed to get device & inode for libc.so");
				close(cfd);
				api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
				return;
			}
			std::tie(rundev, runinode) = fn("libandroid_runtime.so");
			if (!rundev && !runinode) {
				LOGE("#[zygisk::preSpecialize] Failed to get device & inode for libandroid_runtime.so");
				close(cfd);
				api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
				return;
			}
			api->pltHookRegister(rundev, runinode, "unshare", (void*) reshare, (void**) &ar_unshare);
			api->pltHookCommit();
			if (!nodirtyro) {
				if (auto res = robaseby(rundev, runinode)) {
					/*
					 * Temporary workaround to fix detection in apps that checks Shared_Clean
					 * if >= 512kb
					 */
					auto [base, size] = *res;
					long pagesz = sysconf(_SC_PAGESIZE);
					size_t alignedSize = (size + pagesz - 1) & ~(pagesz - 1);
					mprotect(base, alignedSize, PROT_READ | PROT_WRITE);
					for (uintptr_t addr = (uintptr_t) base; addr < (uintptr_t) base + size; addr += pagesz) {
						void* page = reinterpret_cast<void*>(addr);
						uint8_t orig = *(volatile uint8_t*) page;
						*(volatile uint8_t*) page = orig;
					}
					mprotect(base, alignedSize, PROT_READ);
					madvise(base, alignedSize, MADV_REMOVE);
				} else {
					LOGW("#[zygisk::preSpecialize] Failed to get ro block for libandroid_runtime.so");
				}
			}
			std::vector<std::pair<std::unique_ptr<FileDescriptorInfo>, bool>> fdSanitizeList; // bool is shouldDetach
			auto fds = GetOpenFds([](const std::string &error){
				LOGE("#[zygisk::preSpecialize] GetOpenFds: %s", error.c_str());
			});
			if (fds) {
				for (auto &fd : *fds) {
					if (fd == cfd) continue; // Skip companion FD itself
					auto fdi = FileDescriptorInfo::CreateFromFd(fd, [fd](const std::string &error){
						LOGE("#[zygisk::preSpecialize] CreateFromFd(%d): %s", fd, error.c_str());
					});
					if (!fdi)
						continue;
					auto [canSanitize, shouldDetach] = anomaly(std::move(fdi));
					if (canSanitize) {
						fdSanitizeList.emplace_back(std::move(fdi), shouldDetach);
					}
				}
			}

			int res = unshare(CLONE_NEWNS);
			if (res != 0) {
				LOGE("#[zygisk::preSpecialize] unshare: %s", strerror(errno));
				// There's nothing we can do except returning
				close(cfd);
				return;
			}
			res = mount("rootfs", "/", nullptr, MS_SLAVE | MS_REC, nullptr);
			if (res != 0) {
				LOGE("#[zygisk::preSpecialize] mount(rootfs, \"/\", nullptr, MS_SLAVE | MS_REC, nullptr): returned %d: %d (%s)", res, errno, strerror(errno));
				// There's nothing we can do except returning
				close(cfd);
				return;
			}

			static std::vector<MountRuleParser::MountRule> mountRules;

			if (write(cfd, &pid, sizeof(pid)) != sizeof(pid)) {
				LOGE("#[zygisk::preSpecialize] write: [-> pid]: %s", strerror(errno));
				res = FAILURE; // Fallback to unmount from zygote
			} else if (read(cfd, &res, sizeof(res)) != sizeof(res)) {
				LOGE("#[zygisk::preSpecialize] read: [<- status]: %s", strerror(errno));
				res = FAILURE; // Fallback to unmount from zygote
			} else if (res == FAILURE) {
				LOGW("#[zygisk::preSpecialize]: Companion failed, fallback to unmount in zygote process");
				mountRules = MountRuleParser::parseMultipleRules([this]() {
					auto sizeOfRulesPtr = xread<std::size_t>(cfd);
					if (!sizeOfRulesPtr) {
						LOGE("#[zygisk::preSpecialize] read: [sizeOfRules]: %s", strerror(errno));
						return defaultRules;
					}
					auto sizeOfRules = *sizeOfRulesPtr;
					std::vector<std::string> rules(sizeOfRules, "");
					for (int i = 0; i < sizeOfRules; ++i) {
						auto rule = xread<std::string>(cfd);
						if (!rule) {
							LOGE("#[zygisk::preSpecialize] read: [rule (at index %d)]: %s", i, strerror(errno));
							return defaultRules;
						}
						rules[i] = std::move(*rule);
					}
					return rules;
				}());
			}

			close(cfd);

			if (res == FAILURE) {
				LOGW("#[zygisk::preSpecialize]: Companion failed, fallback to unmount in zygote process");
				unmount(mountRules, getMountInfo()); // Unmount in current (zygote) namespace as fallback
			}

			// Sanitize FDs after companion communication and potential mount changes
			for (auto &[fdi, shouldDetach] : fdSanitizeList) {
				LOGD("#[zygisk::preSpecialize]: Sanitizing FD %d (path: %s, socket: %d), detach: %d",
					 fdi->fd, fdi->file_path.c_str(), fdi->is_sock, shouldDetach);
				fdi->ReopenOrDetach([
											fd = fdi->fd,
											path = fdi->file_path // Capture path by value for lambda
									](const std::string &error){
					LOGE("#[zygisk::preSpecialize]: Sanitize FD %d (%s): %s", fd, path.c_str(), error.c_str());
				}, shouldDetach);
			}
			return;
		}
        api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
    }

	void postSpecialize(const char *process) {
        // Unhook PLT hooks
		if (ar_unshare) {
			api->pltHookRegister(rundev, runinode, "unshare", (void*) ar_unshare, nullptr);
            ar_unshare = nullptr; // Clear pointer
        }
		api->pltHookCommit();
		//close(cfd);
		api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
	}

};

static void NoRoot(int fd) {
	pid_t pid = -1, ppid = -1;
	static unsigned int successRate = 0;
	static const std::string description = [] {
		std::ifstream f("/data/adb/modules/zygisk_nohello/description");
		// This file exists only after installing/updating the module
		// It should have the default description
		// Since this is static const it's only evaluated once per boot since companion won't exit
		return f ? ([](std::ifstream& s){ std::string l; std::getline(s, l); return l; })(f) : "A Zygisk module to hide root.";
	}();
	static PropertyManager pm("/data/adb/modules/zygisk_nohello/module.prop");

	static const int compatbility = [] {
		if (fs::exists("/data/adb/modules/zygisk_shamiko") && !fs::exists("/data/adb/modules/zygisk_shamiko/disable"))
			return MODULE_CONFLICT;
		if (fs::exists("/data/adb/modules/zygisk-assistant") && !fs::exists("/data/adb/modules/zygisk-assistant/disable"))
			return MODULE_CONFLICT;
		if (fs::exists("/data/adb/modules/treat_wheel") && !fs::exists("/data/adb/modules/treat_wheel/disable"))
			return MODULE_CONFLICT;
		if (fs::exists("/data/adb/modules/susfs4ksu") && !fs::exists("/data/adb/modules/susfs4ksu/disable"))
			return MODULE_CONFLICT;
		return NORMAL;
	}();

	static const bool doesUmountPersists = []() {
		return fs::exists("/data/adb/nohello/umount_persist") || fs::exists("/data/adb/nohello/umount_persists");
	}();

	static std::vector<std::string> stringRules;
	static std::vector<MountRuleParser::MountRule> mountRules;
	static bool evaluateOnlyOnce = false;

	if (!evaluateOnlyOnce) {
		stringRules = []() {
			std::vector<std::string> rules;
			std::ifstream f("/data/adb/nohello/umount");
			if (f && f.is_open()) {
				std::string line;
				while (std::getline(f, line)) {
					if (!line.empty() && line[0] != '#')
						rules.push_back(line);
				}
				f.close();
			} else {
				rules = defaultRules;
				std::ofstream redef("/data/adb/nohello/umount");
				if (redef && redef.is_open()) {
					for (const auto &rule: rules)
						redef << rule << std::endl;
					redef.close();
				} else
					LOGE("Unable to create `/data/adb/nohello/umount`");
			}
			return rules;
		}();
		mountRules = MountRuleParser::parseMultipleRules(stringRules);
		if (doesUmountPersists)
			evaluateOnlyOnce = true;
	}

	if (read(fd, &ppid, sizeof(ppid)) != sizeof(ppid)) {
		LOGE("#[ps::Companion] Failed to read PPID: %s", strerror(errno));
		close(fd);
		return;
	}

	static const pid_t clrMsgZygote = [ppid]() -> pid_t {
		if (fs::exists("/data/adb/nohello/no_clr_ptracemsg"))
			// Apply the fix only by user's choice
			return ppid;
		if (getKernelVersion() >= KERNEL_VERSION(6, 1, 0))
			// The issue was fixed in 6.1+
			// https://marc.info/?l=linux-arch&m=164124554311501&w=2
			return ppid;
		// Re-work this to avoid issues with bootloops
		// https://github.com/PerformanC/ReZygisk/issues/171
		if (ptrace(PTRACE_ATTACH, ppid, nullptr, nullptr) == -1) {
			LOGE("#[ps::Companion] ptrace(PTRACE_ATTACH, %d, nullptr, nullptr): %s", ppid,
				 strerror(errno));
			return -1;
		}
		waitpid(ppid, nullptr, 0);
		if (ptrace(PTRACE_SYSCALL, ppid, nullptr, nullptr) == -1) {
			LOGE("#[ps::Companion] ptrace(PTRACE_SYSCALL, %d, nullptr, nullptr): %s", ppid, strerror(errno));
			ptrace(PTRACE_DETACH, ppid, nullptr, nullptr);
			return -1;
		}
		waitpid(ppid, nullptr, 0);
		ptrace(PTRACE_DETACH, ppid, nullptr, nullptr);
		LOGD("#[ps::Companion] Cleared ptrace_message for zygote(%d)", ppid);
		return ppid;
	}();

	int result = compatbility;
	if (result == MODULE_CONFLICT) {
		pm.setProp("description", "[" + emoji::emojize(":warning: ") + "Conflicting modules] " + description);
		if (write(fd, &result, sizeof(result)) != sizeof(result)) {
			LOGE("#[ps::Companion] Failed to write result: %s", strerror(errno));
		}
		close(fd);
		return;
	} else {
		if (write(fd, &result, sizeof(result)) != sizeof(result)) {
			LOGE("#[ps::Companion] Failed to write result: %s", strerror(errno));
			close(fd);
			return;
		}
	}

	if (read(fd, &pid, sizeof(pid)) != sizeof(pid)) {
        LOGE("#[ps::Companion] Failed to read PID: %s", strerror(errno));
		close(fd);
		return;
	}

	result = forkcall(
		[pid]()
		{
			int res = switchnsto(pid);
			if (!res) { // switchnsto returns true on success (0 from setns)
				LOGE("#[ps::Companion] Switch namespaces failed for PID %d: %s", pid, strerror(errno));
				return FAILURE;
			}
			auto mounts = getMountInfo();
			unmount(mountRules, mounts);
			remount(mounts);
			return SUCCESS;
		}
	);

	if (result == SUCCESS) {
		successRate++;
		pm.setProp("description", "[" + emoji::emojize(":yum: ") + "Nohello unmounted " +
								  std::to_string(successRate) + " time(s)] " + description);
	} else if (result == FAILURE) {
		if (write(fd, &result, sizeof(result)) != sizeof(result)) {
			LOGE("#[ps::Companion] Failed to write result: %s", strerror(errno));
			close(fd);
			return;
		}
		if (xwrite(fd, stringRules.size())) {
			for (int i = 0; i < stringRules.size(); ++i) {
				if (!xwrite(fd, stringRules[i])) {
					LOGE("#[ps::Companion] write: [rule (at index %d)]: %s", i, strerror(errno));
					close(fd);
					return;
				}
			}
		} else {
			LOGE("#[ps::Companion] write: [stringRules.size()]: %s", strerror(errno));
			close(fd);
			return;
		}
		close(fd);
		return;
	}
	if (write(fd, &result, sizeof(result)) != sizeof(result)) {
		LOGE("#[ps::Companion] Failed to write result: %s", strerror(errno));
		close(fd);
		return;
	}
	close(fd);
}

// Register our module class and the companion handler function
REGISTER_ZYGISK_MODULE(NoHello)
REGISTER_ZYGISK_COMPANION(NoRoot)
