#ifndef SECRET_KEY_H
#define SECRET_KEY_H

#include <pbc/pbc.h>
#include <ibe/ElementList.h>
#include <ibe/PublicKey.h>
#include <ibe/MasterKey.h>
#include "ibe/HIDparam.h"

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


#endif // SECRET_KEY_H