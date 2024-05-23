#ifndef PUBLIC_KEY_H
#define PUBLIC_KEY_H

#include <pbc/pbc.h>
#include <ibe/ElementList.h>
#include <ibe/MasterKey.h>

class PublicKeySong
{
private:
    element_t g, g_1, egg;
    ElementList *h_i, *u_i;

public:
    PublicKeySong(int n, int d, pairing_t &pairing, element_t &MSK);

    element_t *GetG();

    element_t *GetEgg();

    element_t *GetG_1();

    ElementList *GetH();

    ElementList *GetU();

    element_t *GetH_i(int i);

    element_t *GetU_i(int i);

    std::string toString();

    ~PublicKeySong();
};


#endif // PUBLIC_KEY_H