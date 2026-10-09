using System;
using System.Text;
using System.Threading;

class Program
{
    // Голова (меняется только выражение лица)
    static readonly string[][] Heads =
    {
        new[] {
            @"   .-'''-.   ",
            @" @/ ^   ^ \@ ",
            @" @|  \_/  |@ ",
            @"   '-.v.-'   " },
        new[] {
            @"   .-'''-.   ",
            @" @/ o   o \@ ",
            @" @|  \_/  |@ ",
            @"   '-.v.-'   " },
        new[] {
            @"   .-'''-.   ",
            @" @/ ^   - \@ ",
            @" @|  \_/  |@ ",
            @"   '-.v.-'   " },
    };

    // Тело: позы танца
    static readonly string[][] Bodies =
    {
        // руки вверх
        new[] {
            @" \   .|.   / ",
            @"  \_/ | \_/  ",
            @"     /|\     ",
            @"     / \     ",
            @"    /   \    " },
        // наклон влево
        new[] {
            @"  _.-.|.     ",
            @"      /|\_   ",
            @"    _/ | \   ",
            @"   /  /  \   ",
            @"  /    \  \  " },
        // руки в стороны
        new[] {
            @"  ___.|.___  ",
            @"     /|\     ",
            @"    / | \    ",
            @"     / \     ",
            @"    _/ \_    " },
        // наклон вправо
        new[] {
            @"     .|.-._  ",
            @"   _/|\      ",
            @"   / | \_    ",
            @"   /  \  \   ",
            @"  /  /    \  " },
        // прыжок
        new[] {
            @"  \\ .|. //  ",
            @"   \\/|\//   ",
            @"     /|\     ",
            @"    _/ \_    ",
            @"             " },
    };

    static readonly string[] Notes = { "♪", "♫", "♬", "♩" };

    static void Main()
    {
        Console.OutputEncoding = Encoding.UTF8;
        Console.CursorVisible = false;
        Console.Clear();
        Console.CancelKeyPress += (sender, e) =>
        {
            Console.CursorVisible = true;
            Console.ResetColor();
        };

        var rnd = new Random();
        int[] sequence = { 0, 1, 2, 3, 2, 1, 0, 4, 0, 4 }; // порядок поз
        int frame = 0;
        const int left = 6;

        Console.SetCursorPosition(0, 0);
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("  ~ Танцующая девочка ~   (Ctrl+C — выход)");

        while (true)
        {
            int pose = sequence[frame % sequence.Length];
            var head = Heads[frame % Heads.Length];
            var body = Bodies[pose];
            int bounce = pose == 4 ? 0 : 1; // при прыжке поднимается выше

            // Очистка области рисования (без Console.Clear — чтобы не мигало)
            for (int i = 2; i < 14; i++)
            {
                Console.SetCursorPosition(0, i);
                Console.Write(new string(' ', 40));
            }

            int top = 2 + bounce;

            // Голова — розовая
            Console.ForegroundColor = ConsoleColor.Magenta;
            for (int i = 0; i < head.Length; i++)
            {
                Console.SetCursorPosition(left, top + i);
                Console.Write(head[i]);
            }

            // Тело — голубое
            Console.ForegroundColor = ConsoleColor.Cyan;
            for (int i = 0; i < body.Length; i++)
            {
                Console.SetCursorPosition(left, top + head.Length + i);
                Console.Write(body[i]);
            }

            // Летающие нотки
            Console.ForegroundColor = ConsoleColor.Green;
            for (int n = 0; n < 3; n++)
            {
                Console.SetCursorPosition(left + 16 + rnd.Next(0, 10), 2 + rnd.Next(0, 10));
                Console.Write(Notes[rnd.Next(Notes.Length)]);
            }
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.SetCursorPosition(left - 4 - rnd.Next(0, 2), 2 + rnd.Next(0, 10));
            Console.Write(Notes[rnd.Next(Notes.Length)]);

            frame++;
            Thread.Sleep(280);
        }
    }
}
