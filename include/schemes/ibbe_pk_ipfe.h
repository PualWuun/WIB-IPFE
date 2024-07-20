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

class IBBE_PK_IPFE {
    private:
    MasterKeyIBBE *MSK;
    bool init = false;
    pairing_t pairing;
    std::unordered_map<std::string, element_t *> Dlog_table;
    element_t gs_base, gs_step;
    int Dlog_table_len, gslen;

    element_t *myDlog(element_t &target);

    element_t *myDlog_rho(element_t &base, element_t &target, element_t &Zr);

    public:
    int n, decrypt_max;
    PublicKeyIBBE *PK = NULL;

    ElementList *I2Zp(std::vector<int> p, bool zero_padding);

    ElementList *GenZnList(int len);

    void change_type(std::string &param);

    void cleanSetUp();

    PublicKeyIBBE *SetUp(int n);

    CiphertextIBBE *Encrypt(PublicKeyIBBE *PK, ElementList *S, ElementList *x);

    SecretKeyIBBE *KeyGen(PublicKeyIBBE *PK, element_t *ID, ElementList *y);

    element_t *Decrypt(CiphertextIBBE *CT, ElementList *S, SecretKeyIBBE *SK, PublicKeyIBBE *PK);

    void init_dlog(int table_len);

    void init_max_res(int res);

    ~IBBE_PK_IPFE();
};