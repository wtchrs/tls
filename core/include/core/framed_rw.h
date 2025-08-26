#ifndef CORE_FRAME_READER_H
#define CORE_FRAME_READER_H


#include <functional>
#include <optional>
#include <string>

using Read = std::function<std::optional<std::string>()>;
using Write = std::function<void(std::string)>;
using GetLength = std::function<size_t(const std::string &)>;

class FramedReaderWriter {
    const Read read_f_;
    const Write write_f_;
    const std::function<size_t(const std::string &)> get_full_length_;

    std::string received_;

public:
    FramedReaderWriter(const Read read_f, const Write write_f, const GetLength get_full_length)
        : read_f_{read_f}
        , write_f_{write_f}
        , get_full_length_{get_full_length} {}

    std::optional<std::string> read() {
        size_t full_len;
        while ((full_len = get_full_length_(received_)) <= 0 || received_.size() < full_len) {
            if (auto s = read_f_(); s) {
                received_ += *s;
            } else {
                return std::nullopt;
            }
        }
        auto r = received_.substr(0, full_len);
        received_ = received_.substr(full_len);
        return r;
    }

    void write(std::string s) {
        write_f_(s);
    }
};


#endif
