#ifndef CIPHER_TEXT_H
#define CIPHER_TEXT_H

#include <pbc/pbc.h>
#include <ibe/ElementList.h>
#include <ibe/PublicKey.h>
#include "ibe/HIDparam.h"

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


#endif //CIPHER_TEXT_H