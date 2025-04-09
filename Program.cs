using MemoryInjectorLib;

class Program
{
    private static MemoryInjector _injector;

    static void Main(string[] args)
    {
        _injector = new MemoryInjector("FL_2023.exe");
        RunMainLoop();
    }

    private static void RunMainLoop()
    {
        bool running = true;
        while (running)
        {
            DisplayMenu();
            string choice = Console.ReadLine();
            ProcessMenuChoice(choice, ref running);

            if (running)
            {
                WaitForKeyPress();
            }
        }

        HandleUninjection();
        CleanupAndExit();
    }

    private static void DisplayMenu()
    {
        Console.Clear();
        Console.WriteLine("=== Memory Injection Menu ===");
        Console.WriteLine("1. Inject Memory");
        Console.WriteLine("2. UnInject Memory");
        Console.WriteLine("3. Turn ON (Set to 166500.0)");
        Console.WriteLine("4. Turn OFF (Set to 0.0)");
        Console.WriteLine("5. Exit");
        Console.Write("\nPlease select an option (1-5): ");
    }

    private static void ProcessMenuChoice(string choice, ref bool running)
    {
        switch (choice)
        {
            case "1":
                HandleInjection();
                break;
            case "2":
                HandleUninjection();
                break;
            case "3":
                HandleValueChange(166500.0f, "ON");
                break;
            case "4":
                HandleValueChange(0.0f, "OFF");
                break;
            case "5":
                HandleUninjection();
                HandleExit(ref running);
                break;
            default:
                Console.WriteLine("Invalid option. Please try again.");
                break;
        }
    }

    private static void HandleInjection()
    {
        if (_injector.IsInjected)
        {
            Console.WriteLine("Memory is already injected!");
            return;
        }

        if (_injector.Inject())
        {
            Console.WriteLine("Injection successful!");
        }
        else
        {
            Console.WriteLine("Injection failed!");
        }
    }

    private static void HandleUninjection()
    {
        ////if (!_injector.IsInjected)
        ////{
        ////    Console.WriteLine("Memory is not injected yet!");
        ////    return;
        ////}

        if (_injector.UnInject())
        {
            Console.WriteLine("UnInjection successful!");
        }
        else
        {
            Console.WriteLine("UnInjection failed!");
        }
    }

    private static void HandleValueChange(float value, string status)
    {
        if (!_injector.IsInjected)
        {
            Console.WriteLine("Please inject memory first!");
            return;
        }

        if (_injector.SetValue(value))
        {
            Console.WriteLine($"Value set to {status} successfully!");
        }
        else
        {
            Console.WriteLine("Failed to set value!");
        }
    }

    private static void HandleExit(ref bool running)
    {
        running = false;
        if (_injector.IsInjected)
        {
            Console.WriteLine("Cleaning up...");
            _injector.UnInject();
        }
    }

    private static void WaitForKeyPress()
    {
        Console.WriteLine("\nPress any key to continue...");
        Console.ReadKey();
    }

    private static void CleanupAndExit()
    {
        Console.WriteLine("\nPress any key to exit...");
        Console.ReadKey();
    }
}