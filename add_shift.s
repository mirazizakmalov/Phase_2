# Add two values and shift if the second value is >= 5

# data represents words stored in memory.
# Each problem will include .data in the skeleton, which your program will read from
.data
a:
    .word 8
b:
    .word 13
c:
    .word 0

# text starts the declaration of assembly instructions.
.text

# this line points the program to the "main" label.
# each problem must start at the main label, else the program will not run.
.globl main


main: # load the value at a into reg t0
    lui  t4, %hi(a)
    addi t4, t4, %lo(a)
    lw   t0, 0(t4)

    # load the value at b into reg t1
    lui  t4, %hi(b)
    addi t4, t4, %lo(b)
    lw   t1, 0(t4)

    # initialize reg t2 to store the output c
    addi t2, x0, 0  # result (c)

    # initialize comparison for shifting
    addi t3, x0, 5

    # a + b = c
    add t2, t0, t1

    # branch to shift if b is >= 5, else continue to store
    bge t1, t3, shift
    jal x0, store

shift: slli t2, t2, 1 # c << 1
    jal x0, store
    
store:
    # store the value in reg t2 into the memory location of c
    lui  t4, %hi(c)
    addi t4, t4, %lo(c)
    sw   t2, 0(t4)