#ifndef _UFWUTIL_FINGERPRINT_H_
#define _UFWUTIL_FINGERPRINT_H_

#define GFW_TYPE1    0x0101
#define GFW_TYPE1A   0x0102
#define GFW_TYPE2    0x0201
#define GFW_TYPE2A   0x0202

int gfw_fingerprint(const void *ip);
int gfw_fingerprint_sprint(char *s, const void *ip);

#endif /* _UFWUTIL_FINGERPRINT_H_ */
