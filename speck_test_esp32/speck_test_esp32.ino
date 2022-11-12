#define rotate_left(x, n) (((x) >> (word_size - (n))) | ((x) << (n)))
#define rotate_right(x, n) (((x) << (word_size - (n)) | ((x) >> (n))))
unsigned long long ULLONG_MAX = 18446744073709551615;

void Speck_Encrypt_64(const uint8_t *key_schedule, const uint8_t *plaintext, uint8_t *ciphertext);
void Speck_Decrypt_64(const uint8_t *key_schedule, const uint8_t *ciphertext, uint8_t *plaintext);

uint8_t key[] = {0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0x0a, 0x0b, 0x10, 0x11, 0x12, 0x13, 0x18, 0x19, 0x1a, 0x1b};
uint8_t plain[] = {0X2D, 0X43, 0X75, 0X74, 0X74, 0X65, 0X72, 0X3B};
uint8_t buffers[16];
uint8_t key_schedule[576];

unsigned long time1, time2, total_time, avarage;
unsigned long *times;

void setup() {
  Serial.begin(115200);
  uint8_t word_size = 32;
  uint8_t word_bytes = word_size >> 3;
  uint16_t key_words = 4;
  uint64_t sub_keys[4] = {};
  uint64_t mod_mask = ULLONG_MAX >> (word_size);

  for (int i = 0; i < 32; i++) {
    memcpy(&sub_keys[i], key + (word_bytes * i), word_bytes);
  }

  memcpy(key_schedule, &sub_keys[0], word_bytes);

  uint64_t tmp, tmp2;
  for (uint64_t i = 0; i < 27 - 1; i++) {

    tmp = (rotate_right(sub_keys[1], 8)) & mod_mask;
    tmp = (tmp + sub_keys[0]) & mod_mask;
    tmp = tmp ^ i;
    tmp2 = (rotate_left(sub_keys[0], 3)) & mod_mask;
    tmp2 = tmp2 ^ tmp;
    sub_keys[0] = tmp2;

    if (4 != 2) {
      for (int j = 1; j < (key_words - 1); j++) {
        sub_keys[j] = sub_keys[j + 1];
      }
    }
    sub_keys[3] = tmp;

    memcpy(key_schedule + (word_bytes * (i + 1)), &sub_keys[0], word_bytes);
  }

  for (int i = 100; i > 0; i--) {
    time1 = micros();

  Speck_Encrypt_64(key_schedule, plain, buffers);
  Speck_Decrypt_64(key_schedule, buffers, buffers);
  time2 = micros();
    times[i] = time2 - time1;
    }

    printf("finish\n");
    for (int i = 100; i > 0; i--) {
    total_time += times[i];
    }
    printf("total_time:%luus\n", total_time);
    avarage = total_time / 100;
    printf("avarage_time:%luus\n", avarage);

}


void loop() {
}

void Speck_Encrypt_64(const uint8_t *key_schedule, const uint8_t *plaintext,
                      uint8_t *ciphertext) {

  const uint8_t word_size = 32;
  uint32_t *y_word = (uint32_t *)ciphertext;
  uint32_t *x_word = ((uint32_t *)ciphertext) + 1;
  uint32_t *round_key_ptr = (uint32_t *)key_schedule;

  *y_word = *(uint32_t *)plaintext;
  *x_word = *(((uint32_t *)plaintext) + 1);

  for (uint8_t i = 0; i < 27; i++) {
    *x_word = ((rotate_right(*x_word, 8)) + *y_word) ^ *(round_key_ptr + i);
    *y_word = (rotate_left(*y_word, 3)) ^ *x_word;
  }
}

void Speck_Decrypt_64(const uint8_t *key_schedule, const uint8_t *ciphertext,
                      uint8_t *plaintext) {

  const uint8_t word_size = 32;
  uint32_t *y_word = (uint32_t *)plaintext;
  uint32_t *x_word = ((uint32_t *)plaintext) + 1;
  uint32_t *round_key_ptr = (uint32_t *)key_schedule;

  *y_word = *(uint32_t *)ciphertext;
  *x_word = *(((uint32_t *)ciphertext) + 1);

  for (int8_t i = 27 - 1; i >= 0; i--) {
    *y_word = rotate_right((*y_word ^ *x_word), 3);
    *x_word = rotate_left((uint32_t)((*x_word ^ * (round_key_ptr + i)) - *y_word), 8);
  }
}
