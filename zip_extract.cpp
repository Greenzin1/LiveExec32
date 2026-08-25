#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>
#include "unzip.h"

static void mkdirp(const char *path) {
    char tmp[1024];
    snprintf(tmp, sizeof(tmp), "%s", path);
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = 0;
            mkdir(tmp, 0755);
            *p = '/';
        }
    }
    mkdir(tmp, 0755);
}

extern "C" int extract_zip(const char *zip_path, const char *dest_dir) {
    unzFile uf = unzOpen(zip_path);
    if (!uf) return -1;

    unz_global_info gi;
    if (unzGetGlobalInfo(uf, &gi) != UNZ_OK) {
        unzClose(uf);
        return -2;
    }

    char readbuf[8192];
    int err = UNZ_OK;

    for (uLong i = 0; i < gi.number_entry; i++) {
        unz_file_info file_info;
        char filename[1024];
        if (unzGetCurrentFileInfo(uf, &file_info, filename, sizeof(filename), NULL, 0, NULL, 0) != UNZ_OK)
            break;

        char fullpath[2048];
        snprintf(fullpath, sizeof(fullpath), "%s/%s", dest_dir, filename);

        // Create directories
        int len = strlen(fullpath);
        if (fullpath[len - 1] == '/') {
            fullpath[len - 1] = 0;
            mkdirp(fullpath);
            fullpath[len - 1] = '/';
        } else {
            char dir[2048];
            snprintf(dir, sizeof(dir), "%s", fullpath);
            char *slash = strrchr(dir, '/');
            if (slash) {
                *slash = 0;
                mkdirp(dir);
            }
        }

        // Extract file
        if (filename[strlen(filename) - 1] != '/') {
            if (unzOpenCurrentFile(uf) != UNZ_OK) break;

            FILE *fout = fopen(fullpath, "wb");
            if (fout) {
                while ((err = unzReadCurrentFile(uf, readbuf, sizeof(readbuf))) > 0) {
                    fwrite(readbuf, 1, err, fout);
                }
                fclose(fout);
                chmod(fullpath, 0755);
            }
            unzCloseCurrentFile(uf);
        }

        if ((i + 1) < gi.number_entry) {
            if (unzGoToNextFile(uf) != UNZ_OK) break;
        }
    }

    unzClose(uf);
    return 0;
}
