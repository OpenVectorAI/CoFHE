#include <iostream>
#include <fstream>
#include <chrono>

class Benchmark
{
public:
    Benchmark(std::string tag = "") : tag(tag) {}
    ~Benchmark() { this->save(); }

    void run(auto f, size_t n = 1)
    {
        for (size_t i = 0; i < n; i++)
        {
            auto start = std::chrono::high_resolution_clock::now();
            f();
            auto end = std::chrono::high_resolution_clock::now();
            this->timestamps.push_back(std::make_pair(start, end));
        }
        save_if_required();
    }

    void run(auto s, auto f, auto t, size_t n = 1)
    {
        auto setup_ret = s();
        for (size_t i = 0; i < n; i++)
        {
            auto start = std::chrono::high_resolution_clock::now();
            f(setup_ret);
            auto end = std::chrono::high_resolution_clock::now();
            this->timestamps.push_back(std::make_pair(start, end));
        }
        t(setup_ret);
        save_if_required();
    }

    std::vector<std::pair<std::chrono::time_point<std::chrono::high_resolution_clock>, std::chrono::time_point<std::chrono::high_resolution_clock>>> get_timestamps()
    {
        return this->timestamps;
    }

    std::chrono::duration<double, std::milli> average()
    {
        std::chrono::duration<double, std::milli> sum = std::chrono::duration<double, std::milli>::zero();
        for (auto [start, end] : this->timestamps)
        {
            sum += end - start;
        }
        return sum / this->timestamps.size();
    }

    std::chrono::duration<double, std::milli> median()
    {
        std::vector<std::chrono::duration<double, std::milli>> durations;
        for (auto [start, end] : this->timestamps)
        {
            durations.push_back(end - start);
        }
        std::sort(durations.begin(), durations.end());
        return durations[durations.size() / 2];
    }

    std::chrono::duration<double, std::milli> first_run()
    {
        return this->timestamps.front().second - this->timestamps.front().first;
    }

    std::chrono::duration<double, std::milli> last_run()
    {
        return this->timestamps.back().second - this->timestamps.back().first;
    }

    std::chrono::duration<double, std::milli> total()
    {
        std::chrono::duration<double, std::milli> sum = std::chrono::duration<double, std::milli>::zero();
        for (auto [start, end] : this->timestamps)
        {
            sum += end - start;
        }
        return sum;
    }

    void print_summary()
    {
        std::cout << "======================" << std::endl;
        std::cout << "Benchmark summary " + tag << std::endl;
        std::cout << "Number of runs: " << this->timestamps.size() << std::endl;
        std::cout << "First run time: " << this->first_run().count() << "ms" << std::endl;
        std::cout << "Last run time: " << this->last_run().count() << "ms" << std::endl;
        std::cout << "Average time: " << this->average().count() << "ms" << std::endl;
        std::cout << "Median time: " << this->median().count() << "ms" << std::endl;
        std::cout << "Total time: " << this->total().count() << "ms" << std::endl;
        std::cout << "======================" << std::endl;
    }

    void save()
    {
        // add time to filename
        const std::string filename = "./benchmark_results_" + tag + currentDateTime() + ".txt";
        std::ofstream file;
        file.open(filename, std::ios::app);
        file << "======================" << std::endl;
        file << "Benchmark summary " + tag << std::endl;
        file << "Number of runs: " << this->timestamps.size() << std::endl;
        file << "First run time: " << this->first_run().count() << "ms" << std::endl;
        file << "Last run time: " << this->last_run().count() << "ms" << std::endl;
        file << "Average time: " << this->average().count() << "ms" << std::endl;
        file << "Median time: " << this->median().count() << "ms" << std::endl;
        file << "Total time: " << this->total().count() << "ms" << std::endl;
        file << "======================" << std::endl;
        for (auto [start, end] : this->timestamps)
        {
            file << "Start: " << start.time_since_epoch().count() << " End: " << end.time_since_epoch().count() << std::endl;
        }
        file.close();
    }

    void reset()
    {
        this->timestamps.clear();
    }

private:
    std::string tag;
    std::vector<std::pair<std::chrono::time_point<std::chrono::high_resolution_clock>, std::chrono::time_point<std::chrono::high_resolution_clock>>> timestamps;
    std::chrono::time_point<std::chrono::high_resolution_clock> last_save;
    std::string currentDateTime()
    {
        time_t now = time(0);
        struct tm tstruct;
        char buf[80];
        tstruct = *localtime(&now);
        strftime(buf, sizeof(buf), "%Y-%m-%d.%X", &tstruct);
        return buf;
    }

    void save_if_required()
    {
        auto now = std::chrono::high_resolution_clock::now();
        if (now - this->last_save > std::chrono::minutes(10))
        {
            this->save();
            this->last_save = now;
        }
    }
};