#include <ibe/HIDparam.h>

HIDparam::HIDparam(ElementList *ID, ElementList *u_i, ElementList *h_i, element_t *g, element_t *g_1) {
    element_init_same_as(this->g_1_g_ID_1, *g);
    element_init_same_as(this->u_i_h_i_ID_i_times, *g);
    element_set(this->g_1_g_ID_1, *g);
    element_pow_zn(this->g_1_g_ID_1, this->g_1_g_ID_1, *ID->At(1));
    element_div(this->g_1_g_ID_1, *g_1, this->g_1_g_ID_1);

    int d = h_i->len(), l = ID->len();
    this->u_i_h_i = new ElementList(d, 1, *g, false);
    this->u_i_h_i_ID_i = new ElementList(d, 1, *g, false);
    element_set1(this->u_i_h_i_ID_i_times);
    for(int k = 2;k <= d;k++) {
        element_set(*this->u_i_h_i->At(k), *h_i->At(k));
        element_pow_zn(*this->u_i_h_i->At(k), *this->u_i_h_i->At(k), *ID->At(1));
        element_div(*this->u_i_h_i->At(k), *u_i->At(k), *this->u_i_h_i->At(k));
        if(k <= l) {
            element_pow_zn(*this->u_i_h_i_ID_i->At(k), *this->u_i_h_i->At(k), *ID->At(k));
            element_mul(this->u_i_h_i_ID_i_times, this->u_i_h_i_ID_i_times, *this->u_i_h_i_ID_i->At(k));
        }
    }
};

element_t *HIDparam::GetG_1_G_ID_1() {
    return &this->g_1_g_ID_1;
};

element_t *HIDparam::GetU_i_H_i_ID_i_Times() {
    return &this->u_i_h_i_ID_i_times;
};

element_t *HIDparam::GetU_i_H_i(int i) {
    return this->u_i_h_i->At(i);
};

element_t *HIDparam::GetU_i_H_i_ID_i(int i) {
    return this->u_i_h_i_ID_i->At(i);
};

HIDparam::~HIDparam() {
    if(this->u_i_h_i != NULL) delete this->u_i_h_i;
    if(this->u_i_h_i_ID_i != NULL) delete this->u_i_h_i_ID_i;
    element_clear(this->g_1_g_ID_1);
    element_clear(this->u_i_h_i_ID_i_times);
};