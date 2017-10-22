#include <boost/filesystem.hpp>
#include <boost/process/child.hpp>
#include <boost/program_options.hpp>
#include <boost/optional.hpp>

#include <ios>
#include <iostream>
#include <memory>
#include <tuple>
#include <algorithm>

#include <sys/ptrace.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>

#define LOG_DEBUG(M) std::cout << M << "\n";

namespace proc = boost::process;

using Process = std::unique_ptr<proc::child>;
using AddressRange = std::tuple<std::uint64_t, std::uint64_t>;

struct Memory {
    std::string str;
};

struct Diff {
    std::pair<std::string, std::string> rsa_key;
    std::pair<std::vector<std::string>, std::string> addresses;
};

struct MemoryPatch {
    std::uint64_t offset;
    std::string value;
};

AddressRange get_range(const Process& proc) {
    std::string path("/proc/" + std::to_string(proc->id()) + "/maps");
    LOG_DEBUG("Going to read " << path);
    std::ifstream in(path);
    uint64_t from, to;
    char not_used;
    in >> std::hex >> from >> not_used >> std::hex >> to ;
    LOG_DEBUG("Found address range " << std::hex << from << " - " << std::hex << to << std::dec);
    return AddressRange{from, to};
}

Process launch(const std::string& executable) {
    boost::filesystem::path full_path(executable);
    const auto dir_path = full_path.parent_path();
    LOG_DEBUG("Going to " << dir_path);
    boost::filesystem::current_path(dir_path);

    LOG_DEBUG("Going to launch " << executable);
    auto proc = std::make_unique<proc::child>(executable);
    LOG_DEBUG("Done, pid = " << proc->id());
    return proc;
}

boost::optional<Memory> read_range(const Process& proc, const AddressRange& range) {
    using result_t = boost::optional<Memory>;

    const auto pid = proc->id();
    std::uint64_t byte_size = std::get<1>(range) - std::get<0>(range);
    std::uint64_t word_size = byte_size / sizeof(std::uint64_t);
    LOG_DEBUG("Size " << byte_size << " bytes, " << word_size << " words");
    std::unique_ptr<std::uint64_t> ptr(new std::uint64_t[word_size]);

    auto count{word_size};
    auto *in_pointer = reinterpret_cast<std::uint64_t*>(std::get<0>(range));
    std::uint64_t *out_pointer =  reinterpret_cast<std::uint64_t*>(ptr.get());
    while(count) {
        errno = 0;
        auto item = ptrace(PTRACE_PEEKDATA, pid, static_cast<void*>(in_pointer++), NULL);
        if (errno) {
            LOG_DEBUG("Error reading memory :: " << strerror(errno));
            return result_t{};
        }
        *out_pointer++ = static_cast<std::uint64_t>(item);
        --count;
    }
    LOG_DEBUG("Successfully read memory");

    char* from{ reinterpret_cast<char*>(ptr.get()) };
    char* to { reinterpret_cast<char*>(from + byte_size) };

    return result_t{ Memory {std::string{from, to} } };
}

boost::optional<MemoryPatch> patch_rsa(const Process& proc, const Diff& diff, const Memory& memory) {
    using result_t = boost::optional<MemoryPatch>;

    LOG_DEBUG("Searching for RSA-key...");
    auto index = memory.str.find(diff.rsa_key.first);
    if (index != std::string::npos) {
        LOG_DEBUG("Original RSA-key has been found at offset "
            << std::hex << index << std::dec );
        if(diff.rsa_key.second.size() > diff.rsa_key.first.size() ) {
            LOG_DEBUG("New RSA-key cannot be longer then original RSA-key");
            return result_t{};
        }

        std::string new_value(diff.rsa_key.first.size(), 0);
        std::copy(diff.rsa_key.second.cbegin(), diff.rsa_key.second.cend(), new_value.begin());
        return result_t{ MemoryPatch{ index, std::move(new_value) } };
    }
    LOG_DEBUG("Original RSA-key not found");
    return result_t{};
}

boost::optional<std::vector<MemoryPatch>> patch_addresses(const Process& proc, const Diff& diff, const Memory& memory) {
    using result_t = boost::optional<std::vector<MemoryPatch>>;
    std::vector<MemoryPatch> r;
    for(const auto& orig_addr : diff.addresses.first) {
        LOG_DEBUG("Searching for " << orig_addr);
        auto index = memory.str.find(orig_addr);
        if (index != std::string::npos) {
            LOG_DEBUG("... found at offset " << std::hex << index << std::dec);
            const auto new_addr = diff.addresses.second;
            if (orig_addr.size() < new_addr.size()) {
                LOG_DEBUG("Original address " << orig_addr << " cannot be longer then new address " << new_addr);
                return result_t{};
            }
            std::string new_value(orig_addr.size(), 0);
            std::copy(new_addr.cbegin(), new_addr.cend(), new_value.begin());
            r.emplace_back(MemoryPatch{ index, std::move(new_value) });
        }
    }
    return result_t{std::move(r)};
}

void apply_patch(const Process& proc, const AddressRange& range, const std::vector<MemoryPatch>& patches){
    const auto pid = proc->id();
    LOG_DEBUG("Applying " << patches.size() << " memory patches...");
    auto *str_i_pointer = reinterpret_cast<std::uint64_t*>(std::get<0>(range));
    auto *str_c_pointer = reinterpret_cast<char*>(str_i_pointer);
    auto constexpr step = sizeof(long);

    for (const auto& p : patches) {
        auto *c_pointer = str_c_pointer + p.offset;
        auto *i_pointer = reinterpret_cast<std::uint64_t*>(c_pointer);
        auto *end_c_pointer = str_c_pointer + p.offset + p.value.size();
        auto *start_c_pointer = c_pointer;

        while(c_pointer < end_c_pointer) {
            // read value
            errno = 0;
            long value = ptrace(PTRACE_PEEKDATA, pid, static_cast<void*>(c_pointer), NULL);
            auto *value_ptr = reinterpret_cast<char*>(&value);
            if (errno) {
                LOG_DEBUG("Error reading memory :: " << strerror(errno));
                return;
            }
            // update value
            auto *local_end = std::min(c_pointer + step, end_c_pointer);
            auto local_step = local_end - c_pointer;
            auto *src_ptr = p.value.c_str() +  (c_pointer - start_c_pointer);
            auto *src_end = src_ptr + local_step;

            while(src_ptr != src_end) {
                *value_ptr++ = *src_ptr++;
            }
            // write value
            ptrace(PTRACE_POKEDATA, pid, static_cast<void*>(c_pointer), value);
            if (errno) {
                LOG_DEBUG("Error writing memory :: " << strerror(errno));
                return;
            }

            c_pointer = local_end;
        }
    }
}

int patch(const Process& proc, const Diff& diff) {
    const auto pid = proc->id();
    LOG_DEBUG("Attaching to process " << pid);
    if(ptrace(PTRACE_ATTACH, pid, 0, 0)) {
        LOG_DEBUG("ptrace attach error :: " << strerror(errno));
        return 1;
    }
	waitpid(pid, NULL, WUNTRACED);

    LOG_DEBUG("Searching...");
    auto range = get_range(proc);
    auto memory = read_range(proc, range);
    if (memory) {
        auto rsa_update = patch_rsa(proc, diff, *memory);
        auto address_update = patch_addresses(proc, diff, *memory);
        if (rsa_update && address_update) {
            auto updates = *address_update;
            updates.emplace_back(*rsa_update);
            apply_patch(proc, range, updates);
        }
    }

    LOG_DEBUG("Detaching to process " << pid);
    if(ptrace(PTRACE_DETACH, pid, 0, 0)) {
        LOG_DEBUG("ptrace deattach error :: " << strerror(errno));
        return 1;
    }
    return 0;

}

int main(int argc, char** argv) {
    namespace po = boost::program_options;

    po::options_description description("Allowed options");

    description.add_options()
        ("help", "show this help message")
        ("executable", po::value<std::string>(), "Path to Tibia")
        ("rsa_orig", po::value<std::string>(), "Original RSA key")
        ("rsa_new", po::value<std::string>(), "New RSA key")
        ("addresses_orig", po::value<std::vector<std::string>>(), "Old server addresses")
        ("address_new", po::value<std::string>(), "New server address")
        ;

    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, description), vm);
    po::notify(vm);

    bool show_help = vm.count("help") || !vm.count("executable")
        || !vm.count("rsa_orig") || !vm.count("rsa_new")
        || !vm.count("addresses_orig") || !vm.count("address_new")
        ;

    if (show_help) {
        LOG_DEBUG(description);
        return 1;
    }
    const auto &executable = vm["executable"].as<std::string>();
    const Diff diff {
        std::pair<std::string, std::string>{
            vm["rsa_orig"].as<std::string>(),
            vm["rsa_new"].as<std::string>()
        },
        std::pair<std::vector<std::string>, std::string>  {
            vm["addresses_orig"].as<std::vector<std::string>>(),
            vm["address_new"].as<std::string>()
        }
    };

    auto tibia = launch(executable);
    patch(tibia, diff);

    ::sleep(100);
    return 0;
}
