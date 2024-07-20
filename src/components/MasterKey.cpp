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

//TODO: CP
MasterKeyCP::MasterKeyCP(int n, pairing_t &pairing){
    element_init_G1(this->g_1, pairing);
    element_init_G2(this->g_2, pairing);
    element_random(this->g_1);
    element_random(this->g_2);
    element_init_GT(this->eg_1g_2, pairing);
    element_pairing(this->eg_1g_2, this->g_1, this->g_2);
    element_init_Zr(this->s_k, pairing);
    element_random(this->s_k);
    this->n = n;
    
    this->F = std::vector<ElementList *>(n);
    for(int i = 0; i < n; i++){
        this->F[i] = new ElementList(n - i, 0, this->s_k, true);    //F[i] -> [1, n-i]: n-1 elements
    }
};

element_t *MasterKeyCP::GetS_k(){
    return &this->s_k;
};

element_t *MasterKeyCP::GetG_1(){
    return &this->g_1;
};

element_t *MasterKeyCP::GetG_2(){
    return &this->g_2;
};

element_t *MasterKeyCP::GetE_g1_g2(){
    return &this->eg_1g_2;
};

ElementList *MasterKeyCP::GetF_i(int i){
    return this->F[i];
};

element_t *MasterKeyCP::GetF_i_j(int i, int j){
    if(i > j){
        return this->F[j]->At(i);
    }
    return this->F[i]->At(j);
};

std::string MasterKeyCP::toString(){
    int buflen = 1024;
    char buf[buflen];
    std::string res = "MasterKeyCP类\n", tmp;
    element_snprint(buf, buflen, *this->GetS_k());
    tmp = buf;
    res += "s_k: " + tmp + "\n";
    
    for(int i = 0; i < this->n; i++){
        res += this->F[i]->toString(std::to_string(i + 1), "F_i");
        res += "\n";
    }
    return res;
};

MasterKeyCP::~MasterKeyCP(){
    element_clear(this->s_k);
    for(int i = 0; i < this->n; i++){
        if(this->F[i] != NULL){
            delete this->F[i];
            this->F[i] = NULL;
        }
    }
};