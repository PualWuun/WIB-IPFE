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

CipherTextWIB::CipherTextWIB(PublicKeyWIB *PK, ElementList *P, ElementList *x, ElementList *E_G_H_1_Z_i, HIDparamWIB *param){
    int n = x->len(), d = P->len();
    element_t tmp, s;
    element_init_same_as(s, *x->At(1));
    element_random(s);
    this->C_x_i = new ElementList(n, 0, *PK->GetEgg(), false);
    this->P = new ElementList(P,0);
    element_init_same_as(tmp, *PK->GetEgg());
    for(int i = 1;i <= n;i++) {
        element_pow_zn(*this->C_x_i->At(i), *PK->GetEgg(), *x->At(i));
        element_pow_zn(tmp, *E_G_H_1_Z_i->At(i), s);
        element_div(*this->C_x_i->At(i), *this->C_x_i->At(i), tmp);
    }

    element_init_same_as(this->C_1, *PK->GetG());
    element_pow_zn(this->C_1, *param->GetG_1_G_C(), s);

    element_init_same_as(this->C_2, *PK->GetEgg());
    element_set(this->C_2, *PK->GetEgg());
    element_pow_zn(this->C_2, this->C_2, s);

    element_init_same_as(this->C_3, *PK->GetG());
    element_pow_zn(this->C_3, *param->GetU_i_H_i_C_Times(), s);

    element_init_same_as(this->C_4, *PK->GetG());
    element_set1(this->C_4);
    for(int i = 1; i <= d; i++){
        if(element_is0(*P->At(i))){
            element_mul(this->C_4, this->C_4, *param->GetU_i_H_i_C(i));
        }
    }
    element_pow_zn(this->C_4, this->C_4, s);
    element_clear(s);
    element_clear(tmp);
};

element_t *CipherTextWIB::GetC_1(){
    return &this->C_1;
};

element_t *CipherTextWIB::GetC_2(){
    return &this->C_2;
};

element_t *CipherTextWIB::GetC_3(){
    return &this->C_3;
};

element_t *CipherTextWIB::GetC_4(){
    return &this->C_4;
};

ElementList *CipherTextWIB::GetC_x(){
    return this->C_x_i;
};

element_t *CipherTextWIB::GetC_x_i(int i){
    return this->C_x_i->At(i);
};

ElementList *CipherTextWIB::GetP(){
    return this -> P;
};

std::string CipherTextWIB::toString(){
    int buflen = 1024;
    char buf[buflen];
    std::string res = "CipherTextCCA类\n", tmp;
    element_snprint(buf, buflen, *this->GetC_1());
    tmp = buf;
    res += "C_1: " + tmp + "\n";
    element_snprint(buf, buflen, *this->GetC_2());
    tmp = buf;
    res += "C_2: " + tmp + "\n";
    element_snprint(buf, buflen, *this->GetC_3());
    tmp = buf;
    res += "C_3: " + tmp + "\n";
    res += this->C_x_i->toString("n", "C_x_i");
    element_snprint(buf, buflen, *this->GetC_4());
    tmp = buf;
    res += "C_4: " + tmp + "\n";
    return res;
};

CipherTextWIB::~CipherTextWIB(){
    element_clear(C_1);
    element_clear(C_2);
    element_clear(C_3);
    element_clear(C_4);
    if(this->C_x_i != NULL) delete this->C_x_i;
    if(this->P != NULL) delete this->P;
};

CiphertextIBBE::CiphertextIBBE(PublicKeyIBBE *PK, ElementList *S, ElementList *x){
    int s = S->len(), n = x->len();
    element_init_same_as(this->C_0, *PK->GetH());
    element_init_same_as(this->C_1, *PK->GetEgh());
    element_init_same_as(this->C_2, *PK->GetG());
    element_t r, tmp0_0, tmp0_1, tmp1, tmp2, temp1, temp2;
    element_init_same_as(r, *S->At(1));
    element_random(r);
    element_init_same_as(tmp0_0, *S->At(1));
    element_init_same_as(tmp0_1, *S->At(1));
    element_init_same_as(tmp1, *S->At(1));
    element_init_same_as(tmp2, *PK->GetEgh());
    element_init_same_as(temp1, *PK->GetG());
    element_init_same_as(temp2, *PK->GetG());
    element_set(tmp2, *PK->GetEgh());

    this->C_i_1 = new ElementList(n, 0, *PK->GetG(), false);
    this->C_i_2 = new ElementList(n, 0, *PK->GetEgh(), false);

    //TODO: Compute the polynomials (a-ID_1)....(a-ID_s) = a^s + (-1)^{s-1} * C(s,s-1) * a^{s-1} * (ID_1+..ID_s)
    ElementList *ployA = new ElementList(s+1 , 0, *S->At(1), false);
    ElementList *ployB = new ElementList(s+1, 0, *S->At(1), false);
    for(int i = 1; i <= s + 1; i++){
        element_init_same_as(*ployA->At(i), r);
        element_set0(*ployA->At(i));
        element_init_same_as(*ployB->At(i),r);
        element_set0(*ployB->At(i));
    }
    element_set(*ployA->At(1), *S->At(1));
    element_set1(*ployA->At(1));
    for(int i = 2; i <= s+1; i++){
        element_set1(*ployA->At(i+1));
        for(int j = i; j >= 2; j--){
            element_mul(*ployB->At(j), *ployA->At(j), *S->At(i));
            element_mul(*ployA->At(j), *ployA->At(j-1), *ployB->At(j));
        }
        element_mul(*ployA->At(1), *ployA->At(1),*S->At(i));
    }
    element_set1(temp1);
    for(int i = 0; i < s+1; i++){
        element_pow_zn(temp2, *PK->GetH_r_1_alpha_i(i), *ployA->At(i+1));
        element_mul(temp1, temp1, temp2);
    }
    element_set(this->C_2, temp1);
    

    element_pairing(this->C_1, *PK->GetG_r_2_N_2(), *PK->GetH());
    element_pow_zn(this->C_1, this->C_1, r);

    element_pow_zn(this->C_2, *PK->GetG_N_1_alpha(), r);

    for(int i = 1; i <= n; i++){
        element_pow_zn(*this->C_i_1->At(i), *PK->GetG_N_1_alpha_beta_i(i), r);  //g^{n_1ab_i}^r
        element_set1(tmp1);
        element_div(*this->C_i_1->At(1), tmp1, *this->C_i_1->At(i));

        element_pairing(*this->C_i_2->At(i), *PK->GetG_r_2_N_2(), *PK->GetH_beta_i(i));
        element_pow_zn(*this->C_i_2->At(i), *this->C_i_2->At(i), r);
        element_pow_zn(tmp2, tmp2, *x->At(i));
        element_mul(*this->C_i_2->At(i), *this->C_i_2->At(i), tmp2);
    }

    element_clear(r);
    element_clear(tmp0_0);
    element_clear(tmp0_1);
    element_clear(tmp1);
    element_clear(tmp2);

    if(ployA != NULL) delete ployA;
    if(ployB != NULL) delete ployB;
};

element_t *CiphertextIBBE::GetC_0(){
    return &this->C_0;
};

element_t *CiphertextIBBE::GetC_1(){
    return &this->C_1;
};

element_t *CiphertextIBBE::GetC_2(){
    return &this->C_2;
};

ElementList *CiphertextIBBE::GetC_i_1(){
    return this->C_i_1;
};

ElementList *CiphertextIBBE::GetC_i_1(){
    return this->C_i_2;
};

element_t *CiphertextIBBE::GetC_i_1_i(int i){
    return this->C_i_1->At(i);
};

element_t *CiphertextIBBE::GetC_i_2_i(int i){
    return this->C_i_2->At(i);
};

std::string CiphertextIBBE::toString(){
    int buflen = 1024;
    char buf[buflen];
    std::string res = "CipherTextCCA类\n", tmp;
    element_snprint(buf, buflen, *this->GetC_0());
    tmp = buf;
    res += "C_0: " + tmp + "\n";
    element_snprint(buf, buflen, *this->GetC_1());
    tmp = buf;
    res += "C_1: " + tmp + "\n";
    element_snprint(buf, buflen, *this->GetC_2());
    tmp = buf;
    res += "C_2: " + tmp + "\n";
    res += this->C_i_1->toString("n", "C_i_1");
    res += this->C_i_2->toString("n", "C_i_2");
    return res;
};

CiphertextIBBE::~CiphertextIBBE(){
    if(this->C_i_1 != NULL) delete this->C_i_1;
    if(this->C_i_2 != NULL) delete this->C_i_2;
    element_clear(this->C_0);
    element_clear(this->C_1);
    element_clear(this->C_2);
    this->C_i_1 = NULL;
    this->C_i_2 = NULL;
};