#include <ibe/CipherText.h>
#include <openssl/sha.h>
#include <utils/func.h>

CipherTextSong::CipherTextSong(PublicKeySong *PK, ElementList *ID, ElementList *x) {
    int n = x->len(), d = PK->GetU()->len() - 1, l = ID->len();
    element_t tmp, r;
    element_init_same_as(r, *x->At(1));
    element_random(r);

    element_init_same_as(this->C_r, *PK->GetG());
    element_pow_zn(this->C_r, *PK->GetG(), r);

    element_init_same_as(tmp, *PK->GetG());
    element_init_same_as(this->C_u, *PK->GetG());
    element_set(this->C_u, *PK->GetU_i(d + 1));
    for(int i = 1; i <= l; i++) {
        element_pow_zn(tmp, *PK->GetU_i(i), *ID->At(i));
        element_mul(this->C_u, this->C_u, tmp);
    }
    element_pow_zn(this->C_u, this->C_u, r);

    this->C_x_i = new ElementList(n, 0, *PK->GetEgg(), false);
    this->HID = new ElementList(ID, 0);
    element_init_same_as(tmp, *PK->GetEgg());
    for(int i = 1;i <= n;i++) {
        element_pow_zn(*this->C_x_i->At(i), *PK->GetEgg(), *x->At(i));
        element_pairing(tmp, *PK->GetG_1(), *PK->GetH_i(i));
        element_pow_zn(tmp, tmp, r);
        element_mul(*this->C_x_i->At(i), *this->C_x_i->At(i), tmp);
    }

    element_clear(tmp);
    element_clear(r);
};

element_t *CipherTextSong::GetC_r() {
    return &this->C_r;
};

element_t *CipherTextSong::GetC_u() {
    return &this->C_u;
};

ElementList *CipherTextSong::GetC_x() {
    return this->C_x_i;
};

ElementList *CipherTextSong::GetHID() {
    return this->HID;
};

element_t *CipherTextSong::GetC_x_i(int i) {
    return this->C_x_i->At(i);
};

std::string CipherTextSong::toString() {
    int buflen = 1024;
    char buf[buflen];
    std::string res = "CipherTextSong类\n", tmp;
    element_snprint(buf, buflen, *this->GetC_r());
    tmp = buf;
    res += "C_r: " + tmp + "\n";
    element_snprint(buf, buflen, *this->GetC_u());
    tmp = buf;
    res += "C_u: " + tmp + "\n";
    res += this->C_x_i->toString("n", "C_x_i");
    return res;
};

CipherTextSong::~CipherTextSong() {
    element_clear(C_r);
    element_clear(C_u);
    if(this->C_x_i != NULL) delete this->C_x_i;
    if(this->HID != NULL) delete this->HID;
};