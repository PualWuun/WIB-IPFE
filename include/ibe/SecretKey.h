#ifndef SECRET_KEY_H
#define SECRET_KEY_H

#include <pbc/pbc.h>
#include <ibe/ElementList.h>
#include <ibe/PublicKey.h>
#include <ibe/MasterKey.h>
#include <ibe/HIDparam.h>
#include "../data_structure/data_structure.h"
#include "../utils/utils.h"

class SecretKeySong
{
private:
    element_t K_h, K_t;
    ElementList *HID, *y, *K_i;

public:
    SecretKeySong(PublicKeySong *PK, element_t &MSK, ElementList *ID, ElementList *y);

    SecretKeySong(PublicKeySong *PK, SecretKeySong *SK, element_t &IDl);

    element_t *GetK_h();

    element_t *GetK_t();

    ElementList *GetY();

    ElementList *GetK();

    ElementList *GetID();

    element_t *GetID_i(int i);

    element_t *GetY_i(int i);

    element_t *GetK_i(int i);

    std::string toString();

    ~SecretKeySong();
};

class SecretKeyWIB
{
private:
    element_t r_1_zy;
    ElementList *P, *y, *a_i, *b_i, *c_i, *d_i;

public:
    SecretKeyWIB(PublicKeyWIB *PK, MasterKeyWIB *MSK, ElementList *P, ElementList *y, HIDparamWIB *param);

    SecretKeyWIB(PublicKeyWIB *PK, SecretKeyWIB *SK, ElementList *P_new, HIDparamWIB *param);

    element_t *GetR_1_zy();

    ElementList *GetY();

    ElementList *GetC();

    element_t *GetP_i(int i);

    element_t *GetY_i(int i);

    element_t *GetA_i(int i);

    element_t *GetB_i(int i);

    element_t *GetC_i(int i);

    element_t *GetD_i(int i);

    std::string toString();

    ~SecretKeyWIB();
};


class SecretKeyIBBE
{
private:
    element_t K_1, K_2, ID;
    ElementList *y;

public:
    SecretKeyIBBE(PublicKeyIBBE *PK, MasterKeyIBBE *MSK, element_t *ID, ElementList *y);

    element_t *GetK_1();

    element_t *GetK_2();

    element_t *GetID();

    ElementList *GetY();

    std::string toString();

    ~SecretKeyIBBE();
};

class SecretKeyCP{
private:
    std::vector<element_t> *sk_1, *sk_2, *sk_3, *sk_4;
    ElementList *x;
    std::vector<std::string> *attributes;
public:
    SecretKeyCP(MasterKeyCP *MSK, ElementList *x, ElementList *a_k, std::vector<std::string> *attributes);

    ElementList *GetX();

    std::vector<element_t> *GetSK_1();

    element_t *GetSK_1_i(int i);

    std::vector<element_t> *GetSK_2();

    element_t *GetSK_2_i(int i);

    std::vector<element_t> *GetSK_3();

    element_t *GetSK_3_i(int i);

    std::vector<element_t> *GetSK_4();

    element_t *GetSK_4_i(int i);

    std::string toSting();

    ~SecretKeyCP();

};
#endif // SECRET_KEY_H