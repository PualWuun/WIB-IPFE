#include "ibe/MasterKey.h"

MasterKey::MasterKey(int n, pairing_t &pairing)
{
    element_init_Zr(this->alpha, pairing);
    element_random(this->alpha);
    this->z = new ElementList(n, 0, this->alpha, true);
};

element_t *MasterKey::GetAlpha()
{
    return &this->alpha;
};

ElementList *MasterKey::GetZ()
{
    return this->z;
};

element_t *MasterKey::GetZ_i(int i)
{
    return this->z->At(i);
};

std::string MasterKey::toString()
{
    int buflen = 1024;
    char buf[buflen];
    std::string res = "MasterKey类\n", tmp;
    element_snprint(buf, buflen, *this->GetAlpha());
    tmp = buf;
    res += "alpha: " + tmp + "\n";
    res += this->z->toString("n", "z");
    return res;
};
MasterKey::~MasterKey()
{
    if (this->z != NULL)
        delete this->z;
    element_clear(this->alpha);
};

//TODO: WIB
MasterKeyWIB::MasterKeyWIB(int n, pairing_t &pairing){
    element_init_Zr(this->alpha, pairing);
    element_init_same_as(this->r_1, *this->GetAlpha());
    element_random(this->alpha);
    element_random(this->r_1);
    this->z = new ElementList(n, 0, this->alpha, true);
};

element_t *MasterKeyWIB::GetAlpha(){
    return &this->alpha;
};

element_t *MasterKeyWIB::GetR_1(){
    return &this->r_1;
};

ElementList *MasterKeyWIB::GetZ(){
    return this->z;
};

element_t *MasterKeyWIB::GetZ_i(int i){
    return this->z->At(i);
};

std::string MasterKeyWIB::toString(){
    int buflen = 1024;
    char buf[buflen];
    std::string res = "MasterKey类\n", tmp;
    element_snprint(buf, buflen, *this->GetAlpha());
    tmp = buf;
    res += "alpha: " + tmp + "\n";
    element_snprint(buf, buflen, *this->GetR_1());
    tmp = buf;
    res += "r_1: " + tmp + "\n";
    res += this->z->toString("n", "z");
    return res;
};

MasterKeyWIB::~MasterKeyWIB(){
    if(this->z !=NULL) delete this->z;
    element_clear(this->alpha);
    element_clear(this->r_1);
    this->z = NULL;
};


//TODO: IBBE_IPFE
MasterKeyIBBE::MasterKeyIBBE(int n, pairing_t &pairing){
    element_init_Zr(this->alpha, pairing);
    element_init_same_as(this->r_1, *this->GetAlpha());
    element_init_same_as(this->r_2, *this->GetAlpha());
    element_init_same_as(this->n_1, *this->GetAlpha());
    element_init_same_as(this->n_2, *this->GetAlpha());
    element_random(this->alpha);
    element_random(this->r_1);
    element_random(this->r_2);
    element_random(this->n_1);
    element_mul(this->n_2, this->r_1, this->n_1);   //n2 = r_1n_1
    element_div(this->n_2, this->n_2, this->r_2);   //n2 = r_1/r_2*n_1

    this->beta = new ElementList(n, 0, this->alpha, true);
};

element_t *MasterKeyIBBE::GetAlpha(){
    return &this->alpha;
};

element_t *MasterKeyIBBE::GetR_1(){
    return &this->r_1;
};

element_t *MasterKeyIBBE::GetR_2(){
    return &this->r_2;
};

element_t *MasterKeyIBBE::GetN_1(){
    return &this->n_1;
};

element_t *MasterKeyIBBE::GetN_2(){
    return &this->n_2;
};

ElementList *MasterKeyIBBE::GetBeta(){
    return this->beta;
};

element_t *MasterKeyIBBE::GetBeta_i(int i){
    return this->beta->At(i);
};

std::string MasterKeyIBBE::toString(){
    int buflen = 1024;
    char buf[buflen];
    std::string res = "MasterKeyIBBE类\n", tmp;
    element_snprint(buf, buflen, *this->GetAlpha());
    tmp = buf;
    res += "alpha: " + tmp + "\n";
    element_snprint(buf, buflen, *this->GetR_1());
    tmp = buf;
    res += "r_1: " + tmp + "\n";
    element_snprint(buf, buflen, *this->GetR_2());
    tmp = buf;
    res += "r_2: " + tmp + "\n";
    element_snprint(buf, buflen, *this->GetN_1());
    tmp = buf;
    res += "n_1: " + tmp + "\n";
    element_snprint(buf, buflen, *this->GetN_2());
    tmp = buf;
    res += "n_2: " + tmp + "\n";
    res += this->beta->toString("n", "beta");
    return res;
};

MasterKeyIBBE::~MasterKeyIBBE(){
    if(this->beta !=NULL) delete this->beta;
    element_clear(this->alpha);
    element_clear(this->r_1);
    element_clear(this->r_2);
    element_clear(this->n_1);
    element_clear(this->n_2);
    this->beta = NULL;
};