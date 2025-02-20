/* slogger - Simple logger for C++
 * Copyright (c) 2023-2025 Jacob Nilsson
 * Licensed under the MIT license
 */

#pragma once

#include <iostream>
#include <string>
#include <fstream>
#include <ctime>

/**
 * @brief  slogger namespace containing all the classes and functions for the logger.
 */
namespace slogger {
    /**
     * @brief  List of integers representing log types.
     */
    enum class Type {
        Access,
        Error,
        Warning,
        Notice,
        Undefined,
    };

    /**
     * @brief  List of integers representing success or failure.
     */
    enum class Status {
        Success,
        Failure,
        Undefined,
    };

    /**
     * @brief  List of integers representing known output streams
     */
    enum class Stream {
        Stdout,
        Stderr,
        None,
    };

    using LoggerStatus = Status;
    using LoggerErrorType = Type;
    using LoggerStream = Stream;
    using LoggerFile = std::string;
    using LoggerBoolean = bool;
    using LoggerPrefix = std::string;

    /**
     * @brief  Struct containing settings to initialize the logger with.
     */
    struct LoggerProperties {
        LoggerBoolean output_to_std{false};
        LoggerBoolean output_to_file{true};
        LoggerStream stream{Stream::Stderr};
        LoggerBoolean log_date{true};
        LoggerBoolean log_access_to_file{true};
        LoggerBoolean log_error_to_file{true};
        LoggerBoolean log_warning_to_file{true};
        LoggerBoolean log_notice_to_file{true};
        LoggerFile access_log_file{"/var/log/duva/access.log"};
        LoggerFile error_log_file{"/var/log/duva/error.log"};
        LoggerFile warning_log_file{"/var/log/duva/warning.log"};
        LoggerFile notice_log_file{"/var/log/duva/notice.log"};
        LoggerPrefix access_log_prefix{"[ACCESS]: "};
        LoggerPrefix error_log_prefix{"[ERROR]: "};
        LoggerPrefix warning_log_prefix{"[WARNING]: "};
        LoggerPrefix notice_log_prefix{"[NOTICE]: "};
    };

    /**
     * @brief  Struct containing the return values of the logger.
     */
    struct LoggerReturn {
        LoggerErrorType type{Type::Undefined};
        LoggerStatus status{Status::Success};
        LoggerStream stream{Stream::None};
        std::string message{};
        std::string date{};
        std::string data{};
        std::string prefix{};
        std::string file{};
    };

    /**
     * @brief  Class that handles logging.
     */
    class Logger {
        private:
            LoggerProperties prop{};
        public:
            explicit Logger(const LoggerProperties& prop);
            explicit Logger() = default;
            ~Logger() = default;

            LoggerReturn write_to_log(slogger::LoggerErrorType type, const std::string& data) const; // NOLINT
            void override_properties(const LoggerProperties& prop);
            LoggerProperties get();
    };
}

inline slogger::Logger::Logger(const slogger::LoggerProperties& prop) {
    this->prop = prop;
}

inline void slogger::Logger::override_properties(const slogger::LoggerProperties& prop) {
    this->prop = prop;
}

inline slogger::LoggerProperties slogger::Logger::get() {
    return this->prop;
}

inline slogger::LoggerReturn slogger::Logger::write_to_log(const slogger::LoggerErrorType type, const std::string& data) const {
    std::string prefix{"[UNKNOWN]: "};
    std::string logfile{"logfile.txt"};
    slogger::LoggerReturn ret{};

    if (type == slogger::Type::Warning) {
        prefix = prop.warning_log_prefix;
        logfile = prop.warning_log_file;
    } else if (type == slogger::Type::Error) {
        prefix = prop.error_log_prefix;
        logfile = prop.error_log_file;
    } else if (type == slogger::Type::Access) {
        prefix = prop.access_log_prefix;
        logfile = prop.access_log_file;
    } else if (type == slogger::Type::Notice) {
        prefix = prop.notice_log_prefix;
        logfile = prop.notice_log_file;
    } else {
        ret.status = slogger::Status::Failure;
        return ret;
    }

    if (prop.log_date) {
        std::time_t time = std::time(nullptr);
        std::tm local = *std::localtime(&time);

        char buf[20];
        std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &local);

        ret.date = buf;

        prefix += std::string(buf) + ": ";
    }

    ret.prefix = prefix;
    ret.file = logfile;
    ret.type = type;

    if (prop.output_to_std) {
        if (prop.stream == slogger::Stream::Stderr) {
            std::cerr << prefix << data;
        } else if (prop.stream == slogger::Stream::Stdout) {
            std::cout << prefix << data;
        } else {
            ret.status = slogger::Status::Failure;
            return ret;
        }
    }

    ret.message = data;
    ret.data = prefix + data;

    if (prop.output_to_file && logfile.empty() == false) {
        std::ofstream stream(logfile, std::ios::app);

        if (stream.is_open()) {
            stream << prefix << data;
            stream.close();

            ret.status = slogger::Status::Success;
        } else {
            ret.status = slogger::Status::Failure;
        }
    } else {
        ret.status = slogger::Status::Success;
    }

    return ret;
}
