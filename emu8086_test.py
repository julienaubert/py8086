
import unittest
import emu8086


class TestCarryFlagByte(unittest.TestCase):

    def setUp(self):
        self.flags = emu8086.Flags()

    def test_initial(self):
        self.assertFalse(self.flags.cf())

    def test_when_neg_result_sub(self):
        """
                        2 - 5
        
                  0000 0010 
                - 0000 0101

           <=>    0000 0010 
                +11111 1011
            ---------------
                 11111 1101
                                    
            =           509
        """
        self.flags.set_from_sub_operands(2, 5, False)
        self.assertEqual(self.flags.cf(), 1)


    def test_when_pos_result_sub_2comp(self):
        self.flags.set_from_sub_operands(2, 1, False)
        self.assertEqual(self.flags.cf(), 0)

    def test_when_pos_result(self):
        self.flags.set_from_add_result(0b01111111, False)
        self.assertEqual(self.flags.cf(), 0)

    def test_when_zero_result_sub_2comp(self):
        self.flags.set_from_add_result(emu8086.sub_2compl(1, 1, False), False)
        self.assertEqual(self.flags.cf(), 1)

    def test_when_zero_result(self):
        self.flags.set_from_add_result(0, False)
        self.assertEqual(self.flags.cf(), 0)


class TestSignFlagWord(unittest.TestCase):

    def setUp(self):
        self.flags = emu8086.Flags()

    def test_initial_signflag(self):
        self.assertEqual(self.flags.sf(), 0)

    def test_when_neg_result(self):
        self.flags.set_from_sub_operands(0, 1, True)
        self.assertEqual(self.flags.sf(), 1)

    def test_when_pos_result(self):
        self.flags.set_from_add_result(0xf000, True)
        self.assertEqual(self.flags.sf(), 1)


class TestSignFlagByte(unittest.TestCase):

    def setUp(self):
        self.flags = emu8086.Flags()

    def test_initial(self):
        self.assertEqual(self.flags.sf(), 0)

    def test_when_neg_result(self):
        self.flags.set_from_sub_operands(0, 1, False)
        self.assertEqual(self.flags.sf(), 1)

    def test_when_pos_result(self):
        self.flags.set_from_add_result(0xf0, False)
        self.assertTrue(self.flags.sf())



class TestZeroFlag(unittest.TestCase):

    def setUp(self):
        self.flags = emu8086.Flags()

    def test_initial(self):
        self.assertFalse(self.flags.zf())

    def test_when_neg_result(self):
        self.flags.set_from_sub_operands(0, 1, False)
        self.assertFalse(self.flags.zf())

    def test_when_eq_result(self):
        self.flags.set_from_add_result(0, False)
        self.assertTrue(self.flags.zf())

    def test_when_pos_result(self):
        self.flags.set_from_add_result(0xf0, False)
        self.assertFalse(self.flags.zf())



class TestHelpers(unittest.TestCase):

    def test_sgn_ext(self):
        self.assertEqual(emu8086.sgn_ext(0), 0)
        self.assertEqual(emu8086.sgn_ext(0b01111111), 0b01111111)
        self.assertEqual(emu8086.sgn_ext(0b10000000), 0b1111111110000000)
        self.assertEqual(emu8086.sgn_ext(0b10101011), 0b1111111110101011)


    def test_twos_comp_neg1(self):
        self.assertEqual(emu8086.to_2compl(-1, True), 0xffff)

    def test_sub_2compl_overflows(self):
        self.assertEqual(emu8086.sub_2compl(1, 1, True), 0x10000)

    def test_twos_comp(self):
        self.assertEqual(emu8086.to_2compl(0, True), 0)
        self.assertEqual(
                    #                      7654321076543210
                       emu8086.to_2compl(0b0000000001111111, True),
                                         0b0000000001111111
                       )
        self.assertEqual(
                    #                      7654321076543210
                      emu8086.to_2compl(-0b0000000001111111, True),
                                         0b1111111110000001)

    def test_subtract_2compl(self):
        self.assertEqual(emu8086.sub_2compl(0, 1, True), 0xffff)


class TestPushPopState(unittest.TestCase):

    def test_push_pop(self):
        stack = emu8086.WordStack(100)
        stack.set_pos(0x10)
        self.assertEqual(hex(stack.pos()), hex(0x10))
        """
            Value   Address    SP = 0x10
            0x00    0x0C       SP - 4 
            0x00    0x0D       SP - 3 
            0x00    0x0E       SP - 2
            0x00    0x0F       SP - 1
            0x00    0x10       SP
            0x00    0x11       SP + 1
        """

        stack.push(0xabcd)
        self.assertEqual(hex(stack.pos()), hex(0x0e))
        """
            Value   Address    SP = 0x0E
            0x00    0x0C       SP - 2
            0x00    0x0D       SP - 1
            0xCD    0x0E       SP
            0xAB    0x0F       SP + 1
            0x00    0x10       SP + 2
            0x00    0x11       SP + 3
        """

        self.assertEqual(hex(stack.pop()), hex(0xabcd))
        self.assertEqual(hex(stack.pos()), hex(0x10))
        """
            Value   Address    SP = 0x10
            0x00    0x0C       SP - 4
            0x00    0x0D       SP - 3
            0xCD    0x0E       SP - 2
            0xAB    0x0F       SP - 1
            0x00    0x10       SP
            0x00    0x11       SP + 1
        """
        self.assertEqual(hex(stack.pop()), hex(0x0000))


    def test_push_move_1_pop(self):
        stack = emu8086.WordStack(100)
        stack.set_pos(0x10)
        self.assertEqual(hex(stack.pos()), hex(0x10))
        """
            Value   Address    SP = 0x10
            0x00    0x0C       SP - 4 
            0x00    0x0D       SP - 3 
            0x00    0x0E       SP - 2
            0x00    0x0F       SP - 1
            0x00    0x10       SP
            0x00    0x11       SP + 1
        """

        stack.push(0xabcd)
        self.assertEqual(hex(stack.pos()), hex(0x0e))
        """
            Value   Address    SP = 0x0E
            0x00    0x0C       SP - 2
            0x00    0x0D       SP - 1
            0xCD    0x0E       SP
            0xAB    0x0F       SP + 1
            0x00    0x10       SP + 2
            0x00    0x11       SP + 3
        """

        stack.set_pos(stack.pos() - 1)
        self.assertEqual(hex(stack.pos()), hex(0x0d))
        """
            Value   Address    SP = 0x0F
            0x00    0x0C       SP - 1
            0x00    0x0D       SP 
            0xCD    0x0E       SP + 1
            0xAB    0x0F       SP + 2
            0x00    0x10       SP + 3
            0x00    0x11       SP + 4
        """

        self.assertEqual(hex(stack.pop()), hex(0xcd00))
        self.assertEqual(hex(stack.pos()), hex(0x0f))
        """
            Value   Address    SP = 0x0F
            0x00    0x0C       SP - 1
            0x00    0x0D       SP - 2
            0xCD    0x0E       SP - 1
            0xAB    0x0F       SP
            0x00    0x10       SP + 1
            0x00    0x11       SP + 2
        """
        self.assertEqual(hex(stack.pop()), hex(0x00ab))


if __name__ == '__main__':
    unittest.main()
