#pragma once
#include <map>
#include <sstream>
#include "Config.h"

template<class K, class V>
V& map_at(std::map<K, V> &map, K &k) {
	// TODO handle case map.find(k) == map.end()
	return map[k];
}

template <class T> // thanks https://stackoverflow.com/a/947663
std::string to_string(const T& t)
{
	std::stringstream ss;
	ss << t;
	return ss.str();
}