#pragma once
#include <string>
#include <fstream>
#include "json.hpp"
using json = nlohmann::json;

class _Config
{
public:
    _Config() {}
    ~_Config() {}

    bool load_config_file() {
        try
        {
            std::ifstream f("config.json");
            if (!f.good()) {
                return false;
            }
            f >> _data;
            f.close();
        }
        catch (...)
        {
            return false;
        }
    }

    bool save_config_file() {
        try
        {
            std::ofstream f("config.json");
            if (!f.good()) {
                return false;
            }
            f << _data.dump(4);
            f.close();
        }
        catch (...)
        {
            return false;
        }
    }

    void config_set_int(std::string key, int value) {
        _data[key] = value;
    }

    int config_get_int(std::string key, int min, int max, int default_value) {
        try
        {
            if (!_data.contains(key)) {
                return default_value;
            }
            int config = _data[key];
            if (config < min || config > max) {
                return default_value;
            }

            return config;
        }
        catch (...)
        {
            return default_value;
        }
    }

private:
    json _data;
} inline config;
