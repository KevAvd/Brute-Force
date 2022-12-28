using System;
using System.Collections;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace BruteForce
{
    internal class BruteForceEngine
    {
        //Properties
        bool _running = false;
        bool _managerRunning = false;
        HashAlgo _algo = HashAlgo.MD5;
        long _passwordGenerated = 0;
        long _hashGenerated = 0;
        long _hashCompared = 0;
        long _totalWork = 0;
        int _totalHash;
        object _lock1 = new object();
        object _lock2 = new object();
        object _lock3 = new object();

        //Threads
        Thread[] _generatingThreads = new Thread[3];
        Thread[] _hashingThreads = new Thread[7];
        Thread[] _compareThreads = new Thread[1];
        Thread _managerThread;

        //Collections
        List<string> _hash = new List<string>();
        List<Hash> _crackedHash = new List<Hash>();
        ConcurrentQueue<string> _hashQueue = new ConcurrentQueue<string>();
        ConcurrentQueue<Hash> _compareQueue = new ConcurrentQueue<Hash>();

        //Characters set
        string _lowerCase = "abcdefghijklmnopqrstuvwxyz";           //All lower case character
        string _upperCase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";           //All upper case character
        string _numerics = "0123456789";                             //All numeric character
        string _specials = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";     //All special character
        List<char[]> _listOfCharSet = new List<char[]>();

        //Structs
        struct Hash
        {
            public string hash;
            public string password;
        }

        //enums
        public enum HashAlgo
        {
            MD5, SHA1, SHA256, SHA512
        }

        int[] INDEX_CONVERTOR(long index)
        {
            long divider = 1;
            int[] indices = new int[_listOfCharSet.Count];

            for (int i = 0; i < _listOfCharSet.Count; i++)
            {
                if (i > 0) { divider *= _listOfCharSet[i - 1].Length; }
                indices[i] = (int)(index / divider % _listOfCharSet[i].Length);
            }

            return indices;
        }

        public long NBR_OF_COMBINATION()
        {
            long combination = 1;

            for (int i = 0; i < _listOfCharSet.Count; i++)
            {
                combination *= _listOfCharSet[i].Length;
            }

            return combination;
        }

        #region SETUP
        //This region contains all the methods to setup the brute-force engine

        public void Start()
        {
            //Change running state
            _running= true;

            //Starts threads
            START_MANAGER();
            START_GENERATING();
            START_HASHING();
            START_COMPARATING();
        }

        public void Stop()
        {
            _running = false;
            _managerRunning = false;
        }

        public void Wait()
        {
            while (_running) { }
        }

        public void APPEND_CHARSET(bool lowerCase, bool upperCase, bool numerics, bool specials)
        {
            List<char> listChar = new List<char>();

            if (lowerCase) { listChar.AddRange(_lowerCase); }
            if (upperCase) { listChar.AddRange(_upperCase); }
            if (numerics) { listChar.AddRange(_numerics); }
            if (specials) { listChar.AddRange(_specials); }

            _listOfCharSet.Add(listChar.ToArray());
        }

        public void APPEND_CHARSET(char[] charSet)
        {
            _listOfCharSet.Add(charSet);
        }

        public void SWITCH_ALGO(HashAlgo newAlgo)
        {
            _algo = newAlgo;
        }

        public void LOAD_HASHES(string path)
        {
            foreach (string s in File.ReadAllLines(path))
            {
                _hash.Add(s.ToLower());
            }

            _totalHash = _hash.Count;
        }
#endregion

        #region THREADS
        //This region contains all the methods related to threads

        void START_HASHING()
        {
            for(int i = 0; i < _hashingThreads.Length; i++)
            {
                _hashingThreads[i] = new Thread(HASH_PASSWORD);
                _hashingThreads[i].Start();
                Console.WriteLine($"[THREAD {_hashingThreads[i].ManagedThreadId}] [HASH GENERATION] Has started");
            }
        }

        void START_COMPARATING()
        {
            for (int i = 0; i < _compareThreads.Length; i++)
            {
                _compareThreads[i] = new Thread(HASH_COMPARE);
                _compareThreads[i].Start();
                Console.WriteLine($"[THREAD {_compareThreads[i].ManagedThreadId}] [HASH COMPARING] Has started");
            }
        }

        void START_GENERATING()
        {
            long nbrOfPswdPerThreads = NBR_OF_COMBINATION() / _generatingThreads.Length + 1;
            long startIndex = 0;

            for(int i = 0; i < _generatingThreads.Length; i++)
            {
                int[] intArray = INDEX_CONVERTOR(startIndex);
                _generatingThreads[i] = new Thread(() => PASSWORD_GENERATION(intArray, startIndex, startIndex + nbrOfPswdPerThreads));
                _generatingThreads[i].Start();
                startIndex += nbrOfPswdPerThreads;
                Console.WriteLine($"[THREAD {_generatingThreads[i].ManagedThreadId}] [PASSWORD GENERATION] Has started");
            }
        }

        void START_MANAGER()
        {
            _managerRunning = true;
            _managerThread = new Thread(THREADS_MANAGEMENT);
            _managerThread.Start();
        }

        void THREADS_MANAGEMENT()
        {
            //Initialize
            long pswd = 0;
            long hash = 0;
            long compare = 0;

            //Calculate amount of work
            _totalWork = NBR_OF_COMBINATION();

            //Set time
            DateTime start = DateTime.Now;
            double elapsedTime = 0;

            //Event loop
            while (_managerRunning)
            {
                //Get elapsed time
                elapsedTime = (DateTime.Now - start).TotalSeconds;

                if (_hash.Count <= 0 && _running) 
                { 
                    _running = false;
                    Console.WriteLine($"[BRUTE FORCE] Done !!!");
                }

                //Log info
                if(elapsedTime >= 1)
                {
                    //Show info
                    Console.Clear();
                    Console.WriteLine();
                    Console.WriteLine("[INFO]");
                    Console.WriteLine($" => Passwords : {_passwordGenerated} Generated / {_totalWork}");
                    Console.WriteLine($" => Hash : {_hashGenerated} Generated / {_totalWork}");
                    Console.WriteLine($" => Compared : {_hashCompared} compared");
                    Console.WriteLine($" => Passwords frequency : {_passwordGenerated - pswd} Pswd/second");
                    Console.WriteLine($" => Hash frequency : {_hashGenerated - hash} Hash/second");
                    Console.WriteLine($" => Compared frequency : {_hashCompared - compare} Compare/second");
                    Console.WriteLine($" => Passwords carcked : {_crackedHash.Count} / {_totalHash}");
                    for(int i = 0; i < _crackedHash.Count; i++) 
                    {
                        Console.WriteLine($"      => [PASSWORD CRACKED] {_crackedHash[i].password} [{_algo}] {_crackedHash[i].hash}");
                    }
                    Console.WriteLine($" => Running Threads :");
                    Console.WriteLine($"      => [PASSWORD GENERATION]");
                    for (int i = 0; i < _generatingThreads.Length; i++)
                    {
                        if (!_generatingThreads[i].IsAlive) { continue; }
                        Console.WriteLine($"           => [THREAD {_generatingThreads[i].ManagedThreadId}] is running");
                    }
                    Console.WriteLine($"      => [HASHING]");
                    for (int i = 0; i < _hashingThreads.Length; i++)
                    {
                        if (!_hashingThreads[i].IsAlive) { continue; }
                        Console.WriteLine($"           => [THREAD {_hashingThreads[i].ManagedThreadId}] is running");
                    }
                    Console.WriteLine($"      => [COMPARING]");
                    for (int i = 0; i < _compareThreads.Length; i++)
                    {
                        if (!_compareThreads[i].IsAlive) { continue; }
                        Console.WriteLine($"           => [THREAD {_compareThreads[i].ManagedThreadId}] is running");
                    }
                    Console.WriteLine(" => Press Q to quit");
                    if(Console.KeyAvailable && Console.ReadKey(true).Key == ConsoleKey.Q) { Stop(); }
                    Console.WriteLine("[END INFO]");
                    Console.WriteLine();

                    //Save
                    pswd = _passwordGenerated;
                    hash = _hashGenerated;
                    compare = _hashCompared;

                    //Reset time
                    start= DateTime.Now;
                    elapsedTime = 0;
                }
            }
        }
        #endregion

        #region PIPELINE
        /* This region contains all the methods that constitute the brute force pipeline
         * 
         * [] = Pipeline's stage
         * > = Pipeline's stage output
         * => = Queue
         * 
         * [PASSWORD GENERATOR] > PASSWORD => [HASH_PASSWORD] > HASHED PASSWORD => [HASH_COMPARE]
         * 
         * A passwords is first generated, then we hash it, after that we compare it to all the searched hash
         * if there's a match, the hash has been cracked and we put it in a list of cracked hash
         */

        void HASH_COMPARE()
        {
            while (_running)
            {
                //Continue if queue is empty
                if (_compareQueue.IsEmpty) { continue; }

                //Dequeue an hash, compare it to the hash list and put it in carcked hash list if there's a match
                if (_compareQueue.TryDequeue(out Hash toCompare))
                {
                    for (int i = 0; i < _hash.Count; i++)
                    {
                        if (toCompare.hash == _hash[i])
                        {
                            _crackedHash.Add(toCompare);
                            _hash.Remove(_hash[i]);
                            //Console.WriteLine($"[PASSWORD CRACKED] {toCompare.password} [{_algo}] {toCompare.hash}");
                            break;
                        }

                        lock (_lock3)
                        {
                            _hashCompared++;
                        }
                    }
                }
            }

            Console.WriteLine($"[THREAD {Thread.CurrentThread.ManagedThreadId}] [HASH COMPARING] Has ended");
        }

        void HASH_PASSWORD()
        {
            HashAlgorithm halgo = MD5.Create();
            Encoding encoding = Encoding.UTF8;
            StringBuilder builder = new StringBuilder();
            byte[] bytes;

            //Select the hash algorithm
            switch (_algo)
            {
                case HashAlgo.MD5: halgo = MD5.Create(); break;
                case HashAlgo.SHA1: halgo = SHA1.Create(); break;
                case HashAlgo.SHA256: halgo = SHA256.Create(); break;
                case HashAlgo.SHA512: halgo = SHA512.Create(); break;
            }

            while (_running)
            {
                //Continue if queue is empty
                if (_hashQueue.IsEmpty) { continue; }

                //Dequeue a password, hash it and put it in the next queue
                if (_hashQueue.TryDequeue(out string pswd))
                {
                    //Calculate hash
                    Hash hashedPassword = new Hash();
                    hashedPassword.hash = BitConverter.ToString(halgo.ComputeHash(Encoding.UTF8.GetBytes(pswd))).Replace("-", "").ToLower();
                    hashedPassword.password = pswd;

                    //Put it in queue
                    _compareQueue.Enqueue(hashedPassword);

                    lock (_lock2)
                    {
                        _hashGenerated++;
                    }
                }
            }

            Console.WriteLine($"[THREAD {Thread.CurrentThread.ManagedThreadId}] [HASH GENERATION] Has ended");
        }

        void PASSWORD_GENERATION(int[] charIndex, long startIndex, long endIndex)
        {
            char[] password = new char[_listOfCharSet.Count];
            int carry = 1;
            long index = startIndex;

            //Enqueue first password
            for(int i = 0; i < password.Length; i++)
            {
                password[i] = _listOfCharSet[i][charIndex[i]];
            }
            _hashQueue.Enqueue(new string(password));

            while (_running && index <= endIndex)
            {
                carry = 1;
                for (int i = 0; i < charIndex.Length; i++)
                {
                    charIndex[i] += carry;
                    if (charIndex[i] >= _listOfCharSet[i].Length)
                    {
                        charIndex[i] = 0;
                        carry = 1;
                    }
                    else
                    {
                        carry = 0;
                    }
                    password[i] = _listOfCharSet[i][charIndex[i]];
                }

                _hashQueue.Enqueue(new string(password));
                index++;
                lock(_lock1)
                {
                    _passwordGenerated++;
                }
            }

            Console.WriteLine($"[THREAD {Thread.CurrentThread.ManagedThreadId}] [PASSWORD GENERATION] Has ended");
        }
        #endregion
    }
}
