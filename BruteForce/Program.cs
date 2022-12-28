using BruteForce;

BruteForceEngine bfEngine = new BruteForceEngine();
int algo;
bool error = true;
while (error)
{
    Console.Clear();
    Console.WriteLine("[ALGORITHM]");
    Console.WriteLine($" 1) MD5");
    Console.WriteLine($" 2) SHA1");
    Console.WriteLine($" 3) SHA256");
    Console.WriteLine($" 4) SHA512");
    Console.Write("Choose an hashing algorithm : ");
    if (int.TryParse(Console.ReadLine(), out algo) && algo > 0 && algo < 4)
    {
        bfEngine.SWITCH_ALGO((BruteForceEngine.HashAlgo)(algo-1));
        error = false;
    }
}
error = true;
while (error)
{
    Console.Clear();
    Console.Write("Enter file containing hash path : ");
    string path = Console.ReadLine();
    if (File.Exists(path) && Path.GetExtension(path) == ".txt")
    {
        bfEngine.LOAD_HASHES(path);
        error = false;
    }
}
List<string> tokens = new List<string>();
error = true;
while (error)
{
    Console.Clear();
    Console.Write("Enter character set : ");
    string input = Console.ReadLine();
    bool appendMode = false;
    for(int i = 0; i < input.Length; i++)
    {
        if (input[i] == '$') { appendMode = true; tokens.Add(""); }
        if (appendMode && (input[i] == 'l' || input[i] == 'u' || input[i] == 'n' || input[i] == 's')) 
            tokens[tokens.Count - 1] += input[i];
        if (input[i] == ' ') { appendMode = false;}
    }

    foreach(string token in tokens)
    {
        bool lower = false;
        bool upper = false;
        bool num = false;
        bool special = false;

        for (int i = 0; i < token.Length; i++)
        {
            switch(token[i])
            {
                case 'l': lower = true; break;
                case 'u': upper = true; break;
                case 'n': num = true; break;
                case 's': special = true; break;
            }
            bfEngine.APPEND_CHARSET(lower, upper, num, special);
        }
    }

    if(bfEngine.NBR_OF_COMBINATION() > 0) { error = false; }
}

bfEngine.Start();
bfEngine.Wait();

