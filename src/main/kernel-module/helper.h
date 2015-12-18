#ifndef HELPER_H
#define HELPER_H

void binder_data_tostr(uint8_t *data_ptr, uint8_t data_len, char *result);
void print_debug(struct binder_transaction_data tr, uint8_t *data_ptr);

#endif
