#include <iostream>
#include <string>
#include <fstream>

using namespace std;

typedef union uwb {
    unsigned w;
    unsigned char b[4];
} MD5union;

typedef unsigned DigestArray[4];

static unsigned func0(unsigned abcd[]){
    return (abcd[1] & abcd[2]) | (~abcd[1] & abcd[3]);
}

static unsigned func1(unsigned abcd[]){
    return (abcd[3] & abcd[1]) | (~abcd[3] & abcd[2]);
}

static unsigned func2(unsigned abcd[]){
    return  abcd[1] ^ abcd[2] ^ abcd[3];
}

static unsigned func3(unsigned abcd[]){
    return abcd[2] ^ (abcd[1] | ~abcd[3]);
}

typedef unsigned(*DgstFctn)(unsigned a[]);

static unsigned *calctable(unsigned *k)
{
    double s, pwr;
    int i;

    pwr = pow(2.0, 32);
    for (i = 0; i<64; i++) {
        s = fabs(sin(1.0 + i));
        k[i] = (unsigned)(s * pwr);
    }
    return k;
}

static unsigned rol(unsigned r, short N)
{
    unsigned  mask1 = (1 << N) - 1;
    return ((r >> (32 - N)) & mask1) | ((r << N) & ~mask1);
}

static unsigned* MD5Hash(string msg)
{
    int mlen = msg.length();
    static DigestArray h0 = { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476 };
    static DgstFctn ff[] = { &func0, &func1, &func2, &func3 };
    static short M[] = { 1, 5, 3, 7 };
    static short O[] = { 0, 1, 5, 0 };
    static short rot0[] = { 7, 12, 17, 22 };
    static short rot1[] = { 5, 9, 14, 20 };
    static short rot2[] = { 4, 11, 16, 23 };
    static short rot3[] = { 6, 10, 15, 21 };
    static short *rots[] = { rot0, rot1, rot2, rot3 };
    static unsigned kspace[64];
    static unsigned *k;

    static DigestArray h;
    DigestArray abcd;
    DgstFctn fctn;
    short m, o, g;
    unsigned f;
    short *rotn;
    union {
        unsigned w[16];
        char     b[64];
    }mm;
    int os = 0;
    int grp, grps, q, p;
    unsigned char *msg2;

    if (k == NULL) k = calctable(kspace);

    for (q = 0; q<4; q++) h[q] = h0[q];

    {
        grps = 1 + (mlen + 8) / 64;
        msg2 = (unsigned char*)malloc(64 * grps);
        memcpy(msg2, msg.c_str(), mlen);
        msg2[mlen] = (unsigned char)0x80;
        q = mlen + 1;
        while (q < 64 * grps){ msg2[q] = 0; q++; }
        {
            MD5union u;
            u.w = 8 * mlen;
            q -= 8;
            memcpy(msg2 + q, &u.w, 4);
        }
    }

    for (grp = 0; grp<grps; grp++)
    {
        memcpy(mm.b, msg2 + os, 64);
        for (q = 0; q<4; q++) abcd[q] = h[q];
        for (p = 0; p<4; p++) {
            fctn = ff[p];
            rotn = rots[p];
            m = M[p]; o = O[p];
            for (q = 0; q<16; q++) {
                g = (m*q + o) % 16;
                f = abcd[1] + rol(abcd[0] + fctn(abcd) + k[q + 16 * p] + mm.w[g], rotn[q % 4]);

                abcd[0] = abcd[3];
                abcd[3] = abcd[2];
                abcd[2] = abcd[1];
                abcd[1] = f;
            }
        }
        for (p = 0; p<4; p++)
            h[p] += abcd[p];
        os += 64;
    }

    return h;
}

static string GetMD5String(string msg) {
    string str;
    int j, k;
    unsigned *d = MD5Hash(msg);
    MD5union u;
    for (j = 0; j<4; j++){
        u.w = d[j];
        char s[9];
        sprintf(s, "%02x%02x%02x%02x", u.b[0], u.b[1], u.b[2], u.b[3]);
        str += s;
    }

    return str;
}

int main () {
    string DB_path = "../database.txt";
    cout << "1. Sign up" << endl << "2. Sign in" << endl << "x. Exit" << endl;
    while(true) {
        char c = static_cast<char>(getchar());
        if(c == '1') {
            bool exists_flag = false;
            cout << "Enter username: ";
            string username;
            cin >> username;
            string password;
            cout << "Enter password: ";
            cin >> password;
            ifstream fin(DB_path);
            while(!fin.eof()) {
                string name;
                fin >> name;
                if(name == username) {
                    cout << "User already exists!" << endl;
                    exists_flag = true;
                    break;
                }
                fin >> name;
            }
            fin.close();
            if(!exists_flag) {
                ofstream fout(DB_path, fstream::app);
                fout << username << ' ' << GetMD5String(password) << endl;
                cout << "User created" << endl;
                fout.close();
            }
            break;
        } else if (c == '2') {
            bool exists_flag = false;
            cout << "Enter username: ";
            string username;
            cin >> username;
            string password;
            cout << "Enter password: ";
            cin >> password;
            ifstream fin(DB_path);
            while(!fin.eof()) {
                string userdata;
                string name, pswd;
                fin >> name >> pswd;
                if(name == username && GetMD5String(password) == pswd) {
                    cout << "Welcome, " << username << endl;
                    exists_flag = true;
                    break;
                }
            }
            fin.close();
            if(!exists_flag) {
                cout << "Incorrect username or password!";
            }
            break;
        } else if (c == 'x') {
            return 0;
        }
    }
    return 0;
}
