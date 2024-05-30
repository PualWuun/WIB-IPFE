#include <ibe/HIDparam.h>

HIDparamWIB::HIDparamWIB(ElementList *P,ElementList *u_i, ElementList *h_i, element_t *c, element_t *g, element_t *g_1){
    element_init_same_as(this->g_1_g_c, *g);
    element_init_same_as(this->u_i_h_i_c_times, *g);
    element_set(this->g_1_g_c, *g);
    element_pow_zn(this->g_1_g_c, this->g_1_g_c, *c);
    element_div(this->g_1_g_c,*g_1,this->g_1_g_c);

    int d = h_i->len(), l=P->len();
    this->u_i_h_i_c = new ElementList(d, 0, *g, false);
    this->u_i_h_i_c_Pi = new ElementList(d, 0, *g, false);
    element_set1(this->u_i_h_i_c_times);
    for(int i = 1; i <= d; i++){
        element_set(*this->u_i_h_i_c->At(i),*h_i->At(i));
        element_pow_zn(*this->u_i_h_i_c->At(i),*this->u_i_h_i_c->At(i),*c);
        element_div(*this->u_i_h_i_c->At(i), *u_i->At(i), *this->u_i_h_i_c->At(i));
        //TODO: u_ih_i_c_P_i, P_i = * -> P_i = 0;
        if(i < l){
            element_pow_zn(*this->u_i_h_i_c_Pi->At(i), *this->u_i_h_i_c->At(i), *P->At(i));
            element_mul(this->u_i_h_i_c_times, this->u_i_h_i_c_times,*this->u_i_h_i_c_Pi->At(i));
        }
    }
};

element_t *HIDparamWIB::GetG_1_G_C(){
    return &this->g_1_g_c;
};

element_t *HIDparamWIB::GetU_i_H_i_C(int i){
    return this->u_i_h_i_c->At(i);
};

element_t *HIDparamWIB::GetU_i_H_i_C_P_i(int i){
    return this->u_i_h_i_c_Pi->At(i);
};

element_t *HIDparamWIB::GetU_i_H_i_C_Times(){
    return &this->u_i_h_i_c_times;
};

HIDparamWIB::~HIDparamWIB(){
    if(this->u_i_h_i_c!=NULL) delete this->u_i_h_i_c;
    if(this->u_i_h_i_c_Pi !=NULL) delete this->u_i_h_i_c_Pi;
    element_clear(this->g_1_g_c);
    element_clear(this->u_i_h_i_c_times);
};

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