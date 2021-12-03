#ifndef MAPS_H_
#define MAPS_H_

#define LOG(fmt, ...) printf(fmt "\n", ##__VA_ARGS__)
#define LOG_FUNC()    LOG("%s", __func__)

int print_maps(unsigned long start, unsigned long end);
int print_map(char *map, size_t len);

#endif // MAPS_H_
