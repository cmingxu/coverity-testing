#include <stdio.h>
#include <stdlib.h>

typedef int8_t __int8;
typedef char _WORD;

struct V11Struct_t
{
  unsigned int CLUT_offset;
  unsigned char n_in_channels;
};

unsigned int bswap32(unsigned int x) {
  return ((x & 0x000000FF) << 24) |
         ((x & 0x0000FF00) << 8) |
         ((x & 0x00FF0000) >> 8) |
         ((x & 0xFF000000) >> 24);
}

void demo() {
  unsigned int CLUT_offset; // Offset to CLUT data
  unsigned int _CLUT_offset;
  long long input_channel; // Input channel index
  unsigned int Length;
  char *CLUT_data_ptr;
  char *MutableBytePtr;
  int error_flags;
  int TableEntrySizeNotValid;
  int ReservedFieldNotZero;
  int GridpointsValueNotCorrect;
  char v44;
  __int8 number_of_input_channels;


  //

  struct V11Struct_t * v11; // Pointer to V11 structure
  v11 = (struct V11Struct_t *)malloc(sizeof(struct V11Struct_t));

  
  // Get CLUT Offset value from tag data
  CLUT_offset = v11->CLUT_offset;
  if ( !CLUT_offset )
    goto LABEL_95;
  _CLUT_offset = bswap32(CLUT_offset);
  // The vulnerable line is located here
  // The vulnerability will be triggered if _CLUT_offset is
  // equal to length of tag data
  if ( _CLUT_offset > Length )
    goto LABEL_93;
  input_channel = 0LL;
  // Get pointer to CLUT data

  // It will point past the end of the buffer if the vulnerability got triggered
  CLUT_data_ptr = &MutableBytePtr[_CLUT_offset];
  // Get the number of input channels from the header
  number_of_input_channels = (__int8)v11->n_in_channels;
  do
  {
    // if the number of input channels < 16 this branch will be taken
    if ( input_channel >= number_of_input_channels )
    {
       // Possible out-of-bounds read
       if ( CLUT_data_ptr[input_channel] )
       {
         // Change the value of the byte to 0 if it is not 0
         // Out-of-bounds write is triggered here
         CLUT_data_ptr[input_channel] = 0;
         error_flags |= 1u;
         // v17 |= 1u;
       }
    }
    else if ( !CLUT_data_ptr[input_channel] )
    {
      error_flags |= GridpointsValueNotCorrect;
    }
    ++input_channel;
  }
  while ( input_channel != 16 );
  // Possible out-of-bounds read
  v44 = CLUT_data_ptr[16];
  if ( (unsigned int)(v44 - 1) >= 2 )
    error_flags |= TableEntrySizeNotValid;
  if ( CLUT_data_ptr[17] || CLUT_data_ptr[18] || CLUT_data_ptr[19] )
  {
    // Another location that may cause out-of-bounds write
    // if the vulnerability was triggered
    CLUT_data_ptr[19] = 0;
    *(_WORD *)(CLUT_data_ptr + 17) = 0;
    error_flags |= ReservedFieldNotZero;
    // v17 |= 1u;
  }

LABEL_93:
LABEL_95:
  return;

}

int main(int argc, char *argv[])
{
  // Call the demo function
  demo();

  return 0;
}
