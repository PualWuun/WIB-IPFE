#ifndef CIPHER_TEXT_H
#define CIPHER_TEXT_H

#include <pbc/pbc.h>
#include <ibe/ElementList.h>
#include <ibe/PublicKey.h>
#include "ibe/HIDparam.h"
#include "../data_structure/data_structure.h"
#include "../utils/utils.h"

class CipherTextSong {
    private:
    element_t C_r, C_u;
    ElementList *C_x_i, *HID;

    public:
    CipherTextSong(PublicKeySong *PK, ElementList *ID, ElementList *x);

    element_t *GetC_r();

    element_t *GetC_u();

    ElementList *GetC_x();

    element_t *GetC_x_i(int i);

    ElementList *GetHID();

    std::string toString();

    ~CipherTextSong();
};

class CipherTextWIB {
    private:
    element_t C_1, C_2, C_3, C_4;
    ElementList *C_x_i, *P;

    public:
    CipherTextWIB(PublicKeyWIB *PK, ElementList *P, ElementList *x, ElementList *E_G_H_1_Z_i, HIDparamWIB *param);

    element_t *GetC_1();

    element_t *GetC_2();

    element_t *GetC_3();

    element_t *GetC_4();

    ElementList *GetC_x();

    element_t *GetC_x_i(int i);

    ElementList *GetP();

    std::string toString();

    ~CipherTextWIB();
};

class CiphertextIBBE{
private:
    element_t C_0, C_1, C_2;
    ElementList *C_i_1, *C_i_2;

public:
    CiphertextIBBE(PublicKeyIBBE *PK, ElementList *S, ElementList *x);

    element_t *GetC_0();

    element_t *GetC_1();

    element_t *GetC_2();

    ElementList *GetC_i_1();

    ElementList *GetC_i_2();

    element_t *GetC_i_1_i(int i);

    element_t *GetC_i_2_i(int i);

    std::string toString();

    ~CiphertextIBBE();
};

class CiphertextCP{
private:
    element_t c_4;
    std::vector<element_t> *c_1, *c_2, *c_3, *c_5;

    std::string policy;
    access_structure *A;

public:
    CiphertextCP(PublicKeyCP *PK, ElementList *a_c, ElementList *y, std::string policy);

    access_structure* getAccessStructure();

    void setPolicy(string policy);

    string getPolicy();

    element_t *GetC_4();

    std::vector<element_t> *GetC_1();

    element_t *GetC_1_i(int i);

    std::vector<element_t> *GetC_2();

    element_t *GetC_2_i(int i);
    
    std::vector<element_t> *GetC_3();

    element_t *GetC_3_i(int i);
    
    std::vector<element_t> *GetC_5();

    element_t *GetC_5_i(int i);

    std::string toString();

    ~CiphertextCP();
};
#endif //CIPHER_TEXT_H