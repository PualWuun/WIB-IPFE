#include "pbc/pbc.h"
#include "ibe/MasterKey.h"
#include "ibe/PublicKey.h"
#include "ibe/SecretKey.h"
#include "ibe/CipherText.h"
#include "ibe/HIDparam.h"
#include "utils/func.h"
#include "curve/params.h"
#include <unordered_map>
#include <string>

class HID_PK_IPFE {
    private:
    element_t MSK;
    bool init = false;
    pairing_t pairing;
    std::unordered_map<std::string, element_t *> Dlog_table;
    element_t gs_base, gs_step;
    int Dlog_table_len, gslen;

    element_t *myDlog(element_t &target);

    element_t *myDlog_rho(element_t &base, element_t &target, element_t &Zr);

    public:
    int n, d, decrypt_max;
    PublicKeySong *PK = NULL;

    ElementList *I2Zp(std::vector<int> p, bool zero_padding);

    ElementList *GenZnList(int len);

    void change_type(std::string &param);

    void cleanSetUp();

    PublicKeySong *SetUp(int n, int d);

    CipherTextSong *Encrypt(ElementList *HID, ElementList *x);

    CipherTextSong *Encrypt(ElementList *HID, ElementList *x, PublicKeySong *PK);

    SecretKeySong *KeyGen(ElementList *HID, ElementList *y);

    SecretKeySong *KeyGen(ElementList *HID, ElementList *y, PublicKeySong *PK);

    SecretKeySong *Delegate(SecretKeySong *SK, element_t &ID_l1);

    SecretKeySong *Delegate(SecretKeySong *SK, element_t &ID_l1, PublicKeySong *PK);

    element_t *Decrypt(CipherTextSong *CT, SecretKeySong *SK);

    element_t *Decrypt(CipherTextSong *CT, SecretKeySong *SK, PublicKeySong *PK);

    void init_dlog(int table_len);

    void init_max_res(int res);

    ~HID_PK_IPFE();
};