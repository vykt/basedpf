#ifndef _HIDE_H
#define _HIDE_H

#include <linux/limits.h>

//names being hidden do not exceed 16 chars
#define PID_LEN_MAX 8      //max length of filename to hide (keep low)
#define PID_NAME_ENTRIES 2 //number of files to hide, update as needed

//indexes into the string map array
#define FILE_ROOTKIT 0
#define FILE_PID 1


#endif
