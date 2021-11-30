enc_values = [154, 254, 232, 3, 171, 171, 16, 29, 111, 228, 232, 245,
111, 89, 158, 219, 24, 210, 111, 171, 172, 219, 210, 46, 197, 76, 167, 233]

# This is the "encryption" function for the values in the array
# q & Chr((I * 59 - 54) And 255)

print("".join([chr((i * 59 - 54) & 255) for i in enc_values]))