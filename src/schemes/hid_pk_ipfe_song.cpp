#include "schemes/hid_pk_ipfe_song.h"

element_t *HID_PK_IPFE::myDlog_rho(element_t &base, element_t &target, element_t &Zr) {
    static element_t res;
    element_init_same_as(res, Zr);
    element_dlog_pollard_rho(res, base, target);
    return &res;
};

element_t *HID_PK_IPFE::myDlog(element_t &target) {
    if(this->Dlog_table_len == 0) this->init_dlog(100);
    if(this->gslen == 0) this->init_max_res(10000);
    
    element_t *res = (element_t *)(new element_t);
    element_init_same_as(*res, this->gs_step);
    element_set0(*res);
    int buflen = 1024;
    char buf[buflen];
    std::string key;
    for(int i = 0;i < this->gslen;i++) {
        element_snprint(buf, buflen, target);
        key = buf;
        key = H1(key);
        if(this->Dlog_table.find(key) != this->Dlog_table.end()) {
            element_add(*res, *res, *this->Dlog_table[key]);
            return res;
        }
        element_div(target, target, this->gs_base);
        element_add(*res, *res, this->gs_step);
    }
    element_clear(*res);
    return NULL;
};

ElementList *HID_PK_IPFE::I2Zp(std::vector<int> p, bool zero_padding) {
    int len = std::min(this->PK->GetH()->len(), (int)p.size());
    int ele_len = len;
    if(zero_padding) ele_len = this->PK->GetH()->len();
    ElementList *res = new ElementList(ele_len, 0, this->MSK, false);
    for(int i = 0;i < len;i++) element_set_si(*res->At(i + 1), p[i]);
    return res;
}

ElementList *HID_PK_IPFE::GenZnList(int len) {
    return new ElementList(len, 0, this->MSK, true);
};

void HID_PK_IPFE::change_type(std::string &param) {
    pbc_param_t par;
    pbc_param_init_set_str(par, param.c_str());
    pairing_init_pbc_param(this->pairing, par);
    this->init_dlog(0);
    pbc_param_clear(par);
};

void HID_PK_IPFE::cleanSetUp() {
    if(this->PK != NULL) delete this->PK;
    this->PK = NULL;
}

PublicKeySong *HID_PK_IPFE::SetUp(int n, int d) {
    element_init_Zr(this->MSK, this->pairing);
    element_random(this->MSK);
    this->PK = new PublicKeySong(n, d, this->pairing, this->MSK);
    this->n = n;
    this->d = d;
    this->decrypt_max = decrypt_max;
    this->init = true;
    return this->PK;
}

CipherTextSong *HID_PK_IPFE::Encrypt(ElementList *HID, ElementList *x) {
    return this->Encrypt(HID, x, this->PK);
}

CipherTextSong *HID_PK_IPFE::Encrypt(ElementList *HID, ElementList *x, PublicKeySong *PK) {
    return new CipherTextSong(PK, HID, x);
}

SecretKeySong *HID_PK_IPFE::KeyGen(ElementList *HID, ElementList *y) {
    return this->KeyGen(HID, y, this->PK);
}

SecretKeySong *HID_PK_IPFE::KeyGen(ElementList *HID, ElementList *y, PublicKeySong *PK) {
    return new SecretKeySong(PK, this->MSK, HID, y);
}

SecretKeySong *HID_PK_IPFE::Delegate(SecretKeySong *SK, element_t &ID_l1) {
    return this->Delegate(SK, ID_l1, this->PK);
}

SecretKeySong *HID_PK_IPFE::Delegate(SecretKeySong *SK, element_t &ID_l1, PublicKeySong *PK) {
    return new SecretKeySong(PK, SK, ID_l1);
}

element_t *HID_PK_IPFE::Decrypt(CipherTextSong *CT, SecretKeySong *SK) {
    return this->Decrypt(CT, SK, this->PK);
}

element_t *HID_PK_IPFE::Decrypt(CipherTextSong *CT, SecretKeySong *SK, PublicKeySong *PK) {
    element_t target, tmp;

    element_init_same_as(target, *CT->GetC_x_i(1));
    element_set1(target);
    element_init_same_as(tmp, *CT->GetC_x_i(1));
    for(int i = 1;i <= SK->GetY()->len();i++) {
        element_pow_zn(tmp, *CT->GetC_x_i(i), *SK->GetY_i(i));
        element_mul(target, target, tmp);
    }
    element_pairing(tmp, *CT->GetC_r(), *SK->GetK_h());
    element_div(target, target, tmp);
    element_pairing(tmp, *CT->GetC_u(), *SK->GetK_t());
    element_div(target, target, tmp);

    element_t *res = this->myDlog(target);

    element_clear(target);
    element_clear(tmp);
    return res;
}

void HID_PK_IPFE::init_dlog(int table_len) {
    this->gslen = 0;
    for(auto kv: this->Dlog_table) element_clear(*kv.second);
    this->Dlog_table.clear();
    this->Dlog_table_len = table_len;
    if(table_len == 0) return;
    element_t base, res, index, adder;
    element_init_same_as(base, *this->PK->GetEgg());
    element_init_same_as(res, *this->PK->GetEgg());
    element_init_same_as(index, this->MSK);
    element_init_same_as(adder, this->MSK);
    element_set(base, *this->PK->GetEgg());
    element_set0(index);
    element_set1(adder);
    std::string key;
    int buflen = 1024;
    char buf[buflen];
    for(int i = 0;i < this->Dlog_table_len;i++) {
        element_pow_zn(res, base, index);
        element_snprint(buf, buflen, res);
        key = buf;
        key = H1(key);
        this->Dlog_table.insert(std::make_pair(key, (element_t *)(new element_t)));
        element_init_same_as(*this->Dlog_table[key], index);
        element_set(*this->Dlog_table[key], index);
        element_add(index, index, adder);
    }
    element_init_same_as(this->gs_base, *this->PK->GetEgg());
    element_pow_zn(this->gs_base, *this->PK->GetEgg(), index);
    element_init_same_as(this->gs_step, index);
    element_set(this->gs_step, index);

    element_clear(base);
    element_clear(res);
    element_clear(index);
    element_clear(adder);
};

void HID_PK_IPFE::init_max_res(int res) {
    if(this->Dlog_table_len == 0) return;
    this->gslen = (res / this->Dlog_table_len) + 1;
};

HID_PK_IPFE::~HID_PK_IPFE() {
    element_clear(this->MSK);
    if(this->PK != NULL) delete this->PK;
    for(auto kv: this->Dlog_table) delete kv.second;
    pairing_clear(this->pairing);
}
