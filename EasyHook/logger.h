#pragma once

#ifdef _WINDOWS
#include <afxwin.h>
#else
#include <windows.h>
#endif
#include <iostream>
#include <fstream>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <condition_variable>
#include <atomic>
#include <chrono>
#include <sstream>
#include <cstdarg>
#include <iomanip>


class Logger {
public:
	enum LogLevel {
		InfoLevel, WarningLevel, ErrorLevel
	};

	// 单例模式
	static Logger& getInstance() {
		static Logger instance;
		if (instance.pid.empty()) {
			char buf[16] = {};
			sprintf_s(buf, "%d", GetCurrentProcessId());
			instance.pid = buf;
			instance.InitLogFile("C:\\Windows\\Temp", instance.pid);
			instance.enable = true;
		}
		return instance;
	}

	// 禁止拷贝和赋值
	Logger(const Logger&) = delete;
	Logger& operator=(const Logger&) = delete;

	// 写日志，支持 printf 格式化
	void log(const char* file, int line, const char* format, ...) {
		va_list args;
		va_start(args, format);

		std::string message = formatString(format, args);

		va_end(args);

		auto timestamp = getCurrentTimestamp();
		std::string id = pid.empty() ? "" : "[" + pid + "]";

		std::string logEntry = id + "[" + timestamp + "] [" + file + ":" + std::to_string(line) + "] " + message;
		if (enable)
		{
			if (running) {
				std::lock_guard<std::mutex> lock(queueMutex);
				logQueue.push(logEntry);
			} else {
				writeToFile(logEntry);
			}
		}
#ifndef _WINDOWS
#ifdef _DEBUG
		printf(logEntry.c_str());
#endif
#endif
		cv.notify_one(); // 通知写线程
	}

	// 停止日志系统
	void stop() {
		if (!running) return;
		{
			std::lock_guard<std::mutex> lock(queueMutex);
			running = false;  // 设置运行状态
		}
		cv.notify_one();
		if (workerThread.joinable()) {
			workerThread.join();
		}
		for (int i = 0; threadRun && i++ < 1000; Sleep(1));
	}

private:
	// 日志按月份起名
	void InitLogFile(const std::string & dir, const std::string& pid) {
		time_t currentTime = time(nullptr);
		tm* localTime = localtime(&currentTime);
		char timeString[32];
		strftime(timeString, sizeof(timeString), "%Y-%m", localTime);
		char fileName[100];
		sprintf_s(fileName, "\\log_%s_%s.txt", timeString, pid.c_str());
		logFileName = dir + fileName;
	}

	std::string logFileName = "C:\\Windows\\Temp\\log.txt";
	bool enable;						 // 是否启用
	bool threadRun;					     // 日志线程状态
	std::queue<std::string> logQueue;    // 日志队列
	std::mutex queueMutex;               // 队列互斥锁
	std::condition_variable cv;          // 条件变量
	std::atomic<bool> running;           // 是否运行
	std::thread workerThread;            // 后台线程
	std::mutex fileMutex;                // 文件写入锁
	std::string pid;					 // 进程ID

	Logger() : enable(false), threadRun(false), running(true), workerThread(&Logger::processLogs, this) {}

	~Logger() {
		stop();
	}

	// 后台线程处理日志
	void processLogs() {
		threadRun = true;
		while (running) {
			std::unique_lock<std::mutex> lock(queueMutex);
			cv.wait(lock, [this]() {
				return !running || !logQueue.empty(); 
				});

			while (running && !logQueue.empty()) {
				std::string logEntry = logQueue.front();
				logQueue.pop();
				lock.unlock();

				// 写入日志文件
				writeToFile(logEntry);

				lock.lock();
			}
			lock.unlock();
		}
		threadRun = false;
	}

	// 写入文件
	void writeToFile(const std::string& logEntry) {
		std::lock_guard<std::mutex> lock(fileMutex);
		std::ofstream logFile(logFileName, std::ios::app);
		if (logFile.is_open()) {
			logFile << logEntry << std::endl;
		}
	}

	// 获取当前时间戳
	std::string getCurrentTimestamp() {
		auto now = std::chrono::system_clock::now();
		auto in_time_t = std::chrono::system_clock::to_time_t(now);

		std::tm tm;
#ifdef _WIN32
		localtime_s(&tm, &in_time_t);  // Windows 安全版本
#else
		localtime_r(&in_time_t, &tm);  // POSIX 安全版本
#endif

		std::stringstream ss;
		ss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
		return ss.str();
	}

	// 将日志级别转换为字符串
	std::string logLevelToString(LogLevel level) {
		switch (level) {
		case InfoLevel: return "INFO";
		case WarningLevel: return "WARNING";
		case ErrorLevel: return "ERROR";
		default: return "UNKNOWN";
		}
	}

	// 格式化字符串
	std::string formatString(const char* format, va_list args) {
		char buffer[1024];
		vsnprintf(buffer, sizeof(buffer), format, args);
		return std::string(buffer);
	}
};

inline const char* getFileName(const char* path) {
	const char* fileName = strrchr(path, '\\');
	if (!fileName) {
		fileName = strrchr(path, '/');
	}
	return fileName ? fileName + 1 : path;
}

#define Mprintf(format, ...) Logger::getInstance().log(getFileName(__FILE__), __LINE__, format, __VA_ARGS__)
