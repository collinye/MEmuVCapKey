#include "qendian.h"
#include <vector>
#include <string>


/*
typedef unsigned int32_t quint32;
typedef int32_t qint32;
typedef signed char qint8;
typedef unsigned char quint8;
typedef short qint16;
typedef unsigned short quint16;


typedef unsigned char uchar;
typedef unsigned short ushort;
typedef unsigned int uint;
typedef unsigned long ulong;

*/

struct Sha1State {
    quint32 h0;
    quint32 h1;
    quint32 h2;
    quint32 h3;
    quint32 h4;

    quint64 messageSize;
    unsigned char buffer[64];
};

typedef union {
    quint8  bytes[64];
    quint32 words[16];
} Sha1Chunk;

static inline quint32 rol32(quint32 value, unsigned int shift)
{
#ifdef Q_CC_MSVC
    return _rotl(value, shift);
#else
    return ((value << shift) | (value >> (32 - shift)));
#endif
}

static inline quint32 sha1Word(Sha1Chunk *chunk, const uint position)
{
    return (chunk->words[position & 0xf] = rol32(chunk->words[(position + 13) & 0xf]
        ^ chunk->words[(position + 8) & 0xf]
        ^ chunk->words[(position + 2) & 0xf]
        ^ chunk->words[(position) & 0xf], 1));
}

static inline void sha1Round0(Sha1Chunk *chunk, const uint position,
    quint32 &v, quint32 &w, quint32 &x, quint32 &y, quint32 &z)
{
    z += (((w & (x ^ y)) ^ y) + chunk->words[position] + 0x5A827999 + rol32(v, 5));
    w = rol32(w, 30);
}

static inline void sha1Round1(Sha1Chunk *chunk, const uint position,
    quint32 &v, quint32 &w, quint32 &x, quint32 &y, quint32 &z)
{
    z += (((w & (x ^ y)) ^ y) + sha1Word(chunk, position) + 0x5A827999 + rol32(v, 5));
    w = rol32(w, 30);
}

static inline void sha1Round2(Sha1Chunk *chunk, const uint position,
    quint32 &v, quint32 &w, quint32 &x, quint32 &y, quint32 &z)
{
    z += ((w ^ x ^ y) + sha1Word(chunk, position) + 0x6ED9EBA1 + rol32(v, 5));
    w = rol32(w, 30);
}

static inline void sha1Round3(Sha1Chunk *chunk, const uint position,
    quint32 &v, quint32 &w, quint32 &x, quint32 &y, quint32 &z)
{
    z += ((((w | x) & y) | (w & x)) + sha1Word(chunk, position) + 0x8F1BBCDC + rol32(v, 5));
    w = rol32(w, 30);
}

static inline void sha1Round4(Sha1Chunk *chunk, const uint position,
    quint32 &v, quint32 &w, quint32 &x, quint32 &y, quint32 &z)
{
    z += ((w ^ x ^ y) + sha1Word(chunk, position) + 0xCA62C1D6 + rol32(v, 5));
    w = rol32(w, 30);
}


static inline void sha1ProcessChunk(Sha1State *state, const unsigned char *buffer)
{
    // Copy state[] to working vars
    quint32 a = state->h0;
    quint32 b = state->h1;
    quint32 c = state->h2;
    quint32 d = state->h3;
    quint32 e = state->h4;

    quint8 chunkBuffer[64];
    memcpy(chunkBuffer, buffer, 64);

    Sha1Chunk *chunk = reinterpret_cast<Sha1Chunk*>(&chunkBuffer);

    for (int i = 0; i < 16; ++i)
        chunk->words[i] = qFromBigEndian(chunk->words[i]);

    sha1Round0(chunk, 0, a, b, c, d, e); sha1Round0(chunk, 1, e, a, b, c, d); sha1Round0(chunk, 2, d, e, a, b, c); sha1Round0(chunk, 3, c, d, e, a, b);
    sha1Round0(chunk, 4, b, c, d, e, a); sha1Round0(chunk, 5, a, b, c, d, e); sha1Round0(chunk, 6, e, a, b, c, d); sha1Round0(chunk, 7, d, e, a, b, c);
    sha1Round0(chunk, 8, c, d, e, a, b); sha1Round0(chunk, 9, b, c, d, e, a); sha1Round0(chunk, 10, a, b, c, d, e); sha1Round0(chunk, 11, e, a, b, c, d);
    sha1Round0(chunk, 12, d, e, a, b, c); sha1Round0(chunk, 13, c, d, e, a, b); sha1Round0(chunk, 14, b, c, d, e, a); sha1Round0(chunk, 15, a, b, c, d, e);
    sha1Round1(chunk, 16, e, a, b, c, d); sha1Round1(chunk, 17, d, e, a, b, c); sha1Round1(chunk, 18, c, d, e, a, b); sha1Round1(chunk, 19, b, c, d, e, a);
    sha1Round2(chunk, 20, a, b, c, d, e); sha1Round2(chunk, 21, e, a, b, c, d); sha1Round2(chunk, 22, d, e, a, b, c); sha1Round2(chunk, 23, c, d, e, a, b);
    sha1Round2(chunk, 24, b, c, d, e, a); sha1Round2(chunk, 25, a, b, c, d, e); sha1Round2(chunk, 26, e, a, b, c, d); sha1Round2(chunk, 27, d, e, a, b, c);
    sha1Round2(chunk, 28, c, d, e, a, b); sha1Round2(chunk, 29, b, c, d, e, a); sha1Round2(chunk, 30, a, b, c, d, e); sha1Round2(chunk, 31, e, a, b, c, d);
    sha1Round2(chunk, 32, d, e, a, b, c); sha1Round2(chunk, 33, c, d, e, a, b); sha1Round2(chunk, 34, b, c, d, e, a); sha1Round2(chunk, 35, a, b, c, d, e);
    sha1Round2(chunk, 36, e, a, b, c, d); sha1Round2(chunk, 37, d, e, a, b, c); sha1Round2(chunk, 38, c, d, e, a, b); sha1Round2(chunk, 39, b, c, d, e, a);
    sha1Round3(chunk, 40, a, b, c, d, e); sha1Round3(chunk, 41, e, a, b, c, d); sha1Round3(chunk, 42, d, e, a, b, c); sha1Round3(chunk, 43, c, d, e, a, b);
    sha1Round3(chunk, 44, b, c, d, e, a); sha1Round3(chunk, 45, a, b, c, d, e); sha1Round3(chunk, 46, e, a, b, c, d); sha1Round3(chunk, 47, d, e, a, b, c);
    sha1Round3(chunk, 48, c, d, e, a, b); sha1Round3(chunk, 49, b, c, d, e, a); sha1Round3(chunk, 50, a, b, c, d, e); sha1Round3(chunk, 51, e, a, b, c, d);
    sha1Round3(chunk, 52, d, e, a, b, c); sha1Round3(chunk, 53, c, d, e, a, b); sha1Round3(chunk, 54, b, c, d, e, a); sha1Round3(chunk, 55, a, b, c, d, e);
    sha1Round3(chunk, 56, e, a, b, c, d); sha1Round3(chunk, 57, d, e, a, b, c); sha1Round3(chunk, 58, c, d, e, a, b); sha1Round3(chunk, 59, b, c, d, e, a);
    sha1Round4(chunk, 60, a, b, c, d, e); sha1Round4(chunk, 61, e, a, b, c, d); sha1Round4(chunk, 62, d, e, a, b, c); sha1Round4(chunk, 63, c, d, e, a, b);
    sha1Round4(chunk, 64, b, c, d, e, a); sha1Round4(chunk, 65, a, b, c, d, e); sha1Round4(chunk, 66, e, a, b, c, d); sha1Round4(chunk, 67, d, e, a, b, c);
    sha1Round4(chunk, 68, c, d, e, a, b); sha1Round4(chunk, 69, b, c, d, e, a); sha1Round4(chunk, 70, a, b, c, d, e); sha1Round4(chunk, 71, e, a, b, c, d);
    sha1Round4(chunk, 72, d, e, a, b, c); sha1Round4(chunk, 73, c, d, e, a, b); sha1Round4(chunk, 74, b, c, d, e, a); sha1Round4(chunk, 75, a, b, c, d, e);
    sha1Round4(chunk, 76, e, a, b, c, d); sha1Round4(chunk, 77, d, e, a, b, c); sha1Round4(chunk, 78, c, d, e, a, b); sha1Round4(chunk, 79, b, c, d, e, a);

    // Add the working vars back into state
    state->h0 += a;
    state->h1 += b;
    state->h2 += c;
    state->h3 += d;
    state->h4 += e;

    // Wipe variables
#ifdef SHA1_WIPE_VARIABLES
    a = b = c = d = e = 0;
    memset(chunkBuffer, 0, 64);
#endif
}



static void sha1Update(Sha1State *state, const unsigned char *data, qint64 len)
{
    quint32 rest = static_cast<quint32>(state->messageSize & Q_UINT64_C(63));

    quint64 availableData = static_cast<quint64>(len) + static_cast<quint64>(rest);
    state->messageSize += len;

    if (availableData < Q_UINT64_C(64)) {
        memcpy(&state->buffer[rest], &data[0], (size_t)len);

    } else {
        qint64 i = static_cast<qint64>(64 - rest);
        memcpy(&state->buffer[rest], &data[0], static_cast<qint32>(i));
        sha1ProcessChunk(state, state->buffer);

        qint64 lastI = len - ((len + rest) & Q_INT64_C(63));
        for (; i < lastI; i += 64)
            sha1ProcessChunk(state, &data[i]);

        memcpy(&state->buffer[0], &data[i], (size_t)(len - i));
    }
}


static void sha1InitState(Sha1State *state)
{
    state->h0 = 0x67452301;
    state->h1 = 0xEFCDAB89;
    state->h2 = 0x98BADCFE;
    state->h3 = 0x10325476;
    state->h4 = 0xC3D2E1F0;

    state->messageSize = 0;
}

///////////////////////////////

static inline void sha1FinalizeState(Sha1State *state)
{
    quint64 messageSize = state->messageSize;
    unsigned char sizeInBits[8];
    qToBigEndian(messageSize << 3, sizeInBits);

    sha1Update(state, (const unsigned char *)"\200", 1);

    unsigned char zero[64];
    memset(zero, 0, 64);
    if (static_cast<int>(messageSize & 63) > 56 - 1) {
        sha1Update(state, zero, 64 - 1 - static_cast<int>(messageSize & 63));
        sha1Update(state, zero, 64 - 8);
    } else {
        sha1Update(state, zero, 64 - 1 - 8 - static_cast<int>(messageSize & 63));
    }

    sha1Update(state, sizeInBits, 8);
#ifdef SHA1_WIPE_VARIABLES
    memset(state->buffer, 0, 64);
    memset(zero, 0, 64);
    state->messageSize = 0;
#endif
}

static inline void sha1ToHash(Sha1State *state, unsigned char* buffer)
{
    qToBigEndian(state->h0, buffer);
    qToBigEndian(state->h1, buffer + 4);
    qToBigEndian(state->h2, buffer + 8);
    qToBigEndian(state->h3, buffer + 12);
    qToBigEndian(state->h4, buffer + 16);
}

std::string toHex(char* pData, int len)
{
    std::vector<char> strHex;
    strHex.resize(len * 2 + 1);
    char *hexData = strHex.data();
    const uchar *data = (const uchar *)pData;
    for (int i = 0; i < len; ++i) {
        int j = (data[i] >> 4) & 0xf;
        if (j <= 9)
            hexData[i * 2] = (j + '0');
        else
            hexData[i * 2] = (j + 'a' - 10);
        j = data[i] & 0xf;
        if (j <= 9)
            hexData[i * 2 + 1] = (j + '0');
        else
            hexData[i * 2 + 1] = (j + 'a' - 10);
    }
    strHex[strHex.size() - 1] = '\0';
    return strHex.data();
}


std::string hash(const char* data, int length)
{
    std::vector<char> result;
    Sha1State sha1Context;
    sha1InitState(&sha1Context);
    sha1Update(&sha1Context, (const unsigned char *)data, length);

    Sha1State copy = sha1Context;
    result.resize(20);
    sha1FinalizeState(&copy);
    sha1ToHash(&copy, (unsigned char *)result.data());
    return toHex(result.data(), result.size());
}


//////////////////////////////

void StringReplace(std::string &strBase, std::string strSrc, std::string strDes)
{
    std::string::size_type pos = 0;
    std::string::size_type srcLen = strSrc.size();
    std::string::size_type desLen = strDes.size();
    pos = strBase.find(strSrc, pos);
    while ((pos != std::string::npos)) {
        strBase.replace(pos, srcLen, strDes);
        pos = strBase.find(strSrc, (pos + desLen));
    }
}

// key stands for the name of shared memory name.
std::string makePlatformWinSafeKey(const std::string &key)
{
    if (key.empty())
        return std::string();

    std::string result = "qipc_sharedmemory_";
    std::vector<char> vec;
    for (int i = 0; i < (int)key.length(); ++i) {
        if ((key[i] >= 'a' && key[i] <= 'z') ||
            (key[i] >= 'A' && key[i] <= 'Z')) {
            vec.push_back(key[i]);
        }
    }
    vec.push_back('\0');
    result.append(vec.data());

    std::string hex = hash(key.c_str(), key.length());
    result.append(hex);
    return result;
}

extern "C"
int makeVCapKey(const char * name, char * key, size_t key_len) {
    std::string k = name;
    k.append("_ImgSharedMemory");
    std::string r = makePlatformWinSafeKey(k);
    if (key_len > r.length()) {
        memcpy(key, r.c_str(), r.length());
        key[r.length()] = '\0';
    }
    return r.length();
}

/*
int main(const int argc, const char* argv[])
{
    char key[128];
    makeVCapKey("MEmu_1", key, sizeof(key));
    fprintf(stderr, "key: %s\n", key);
    return 0;
//    std::string m_strSMImageName = makePlatformWinSafeKey("MEmu_1" + "_ImgSharedMemory");
}
*/

