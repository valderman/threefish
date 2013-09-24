typedef unsigned long long W64;
W64 key_const = 0x1BD11BDAA9FC1A22;
#define rl(x, b) (((x) << ((b) & 63)) | ((x) >> ((64-(b)) & 63)))
#define rr(x, b) (((x) >> ((b) & 63)) | ((x) << ((64-(b)) & 63)))

void encrypt256(W64*, W64*, W64*, W64*);
void decrypt256(W64*, W64*, W64*, W64*);
