using System;
using Xunit;
using System.IO;

using IIG.CoSFE.DatabaseUtils;
using IIG.BinaryFlag;
using IIG.DatabaseConnectionUtils;
using IIG.FileWorker;
using IIG.PasswordHashingUtils;

    // BF -> file
    // PHash -> DB

namespace XUnitTestProject3{
    public class UnitTest1 {



        private const string Server = @"DESKTOP-4ENV6NA";
        private const string Database = @"IIG.CoSWE.AuthDB";
        private const bool   IsTrusted = true;
        private const string Login = @"sa";
        // private const string Password = @"L}EjpfCgru9X@GLj";
        private const string Password = @"1";
        private const int    ConnectionTimeout = 75;

        public  string testPassword = PasswordHasher.GetHash("aww");
        public string  testLogin = PasswordHasher.GetHash("wswwwwwwww");

        public string updatePassword = PasswordHasher.GetHash("newpass");
        public string updateLogin = PasswordHasher.GetHash("update");

        private string dirName = "fileWorkerTest";

        [Fact]
        public void TestFile_Creating_Directory_File_AndInputFalse(){
           string mkdirPAth = BaseFileWorker.MkDir(dirName);
           Assert.NotEmpty(mkdirPAth);
           MultipleBinaryFlag Flag = new MultipleBinaryFlag(10);
           Flag.ResetFlag(4);
           BaseFileWorker.Write(Flag.GetFlag().ToString(), mkdirPAth + "\\" + "test.txt");
           Assert.Equal(Flag.GetFlag().ToString(), BaseFileWorker.ReadAll(mkdirPAth + "\\" + "test.txt"));
           
        }

        [Fact]
        public void TestFile_FlagLength_0(){
            string mkdirPAth = BaseFileWorker.MkDir(dirName);
            MultipleBinaryFlag Flag = new MultipleBinaryFlag(0);
            BaseFileWorker.Write(Flag.GetFlag().ToString(), mkdirPAth + "\\" + "test.txt");
            Assert.Equal(Flag.GetFlag().ToString(), BaseFileWorker.ReadAll(mkdirPAth + "\\" + "test.txt"));
        }

        [Fact]
        public void TestFile_FlagLength_1()
        {
            string mkdirPAth = BaseFileWorker.MkDir(dirName);
            MultipleBinaryFlag Flag = new MultipleBinaryFlag(1);
            BaseFileWorker.Write(Flag.GetFlag().ToString(), mkdirPAth + "\\" + "test.txt");
            Assert.Equal(Flag.GetFlag().ToString(), BaseFileWorker.ReadAll(mkdirPAth + "\\" + "test.txt"));
        }

        [Fact]
        public void TestFile_FlagLength_2()
        {
            string mkdirPAth = BaseFileWorker.MkDir(dirName);
            MultipleBinaryFlag Flag = new MultipleBinaryFlag(2);
            BaseFileWorker.Write(Flag.GetFlag().ToString(), mkdirPAth + "\\" + "test.txt");
            Assert.Equal(Flag.GetFlag().ToString(), BaseFileWorker.ReadAll(mkdirPAth + "\\" + "test.txt"));
        }



        [Fact]
        public void TestFile_FlagLength_17179868703()
        {
            string mkdirPAth = BaseFileWorker.MkDir(dirName);
            MultipleBinaryFlag Flag = new MultipleBinaryFlag(17179868703);
            BaseFileWorker.Write(Flag.GetFlag().ToString(), mkdirPAth + "\\" + "test.txt");
            Assert.Equal(Flag.GetFlag().ToString(), BaseFileWorker.ReadAll(mkdirPAth + "\\" + "test.txt"));
        }

        [Fact]
        public void TestFile_FlagLength_17179868704()
        {
            string mkdirPAth = BaseFileWorker.MkDir(dirName);
            MultipleBinaryFlag Flag = new MultipleBinaryFlag(17179868704);
            BaseFileWorker.Write(Flag.GetFlag().ToString(), mkdirPAth + "\\" + "test.txt");
            Assert.Equal(Flag.GetFlag().ToString(), BaseFileWorker.ReadAll(mkdirPAth + "\\" + "test.txt"));
        }

        [Fact]
        public void TestFile_FlagLength_17179868705()
        {
            string mkdirPAth = BaseFileWorker.MkDir(dirName);
            MultipleBinaryFlag Flag = new MultipleBinaryFlag(17179868705);
            BaseFileWorker.Write(Flag.GetFlag().ToString(), mkdirPAth + "\\" + "test.txt");
            Assert.Equal(Flag.GetFlag().ToString(), BaseFileWorker.ReadAll(mkdirPAth + "\\" + "test.txt"));
        }

        [Fact]
        public void TestFile_Output_False()
        {
            string mkdirPAth = BaseFileWorker.MkDir(dirName);
            MultipleBinaryFlag Flag = new MultipleBinaryFlag(22);
            Flag.ResetFlag(4);
            BaseFileWorker.Write(Flag.GetFlag().ToString(), mkdirPAth + "\\" + "test.txt");
            MultipleBinaryFlag FlagFalse = new MultipleBinaryFlag(22, Convert.ToBoolean(BaseFileWorker.ReadAll(mkdirPAth + "\\" + "test.txt")));
            Assert.False(FlagFalse.GetFlag());

        }


          [Fact]
        public void TestDB_AddCredentials(){
            AuthDatabaseUtils authDB = new AuthDatabaseUtils(Server, Database, IsTrusted, Login, Password, ConnectionTimeout);
            // Assert.True(authDB.AddCredentials("wswwwwwww", testPassword));
            authDB.AddCredentials(testLogin, testPassword);
            Assert.True(authDB.CheckCredentials(testLogin, testPassword));

        }

        [Fact]
        public void TestDB2_UpdateCredentials() {
            AuthDatabaseUtils authDB = new AuthDatabaseUtils(Server, Database, IsTrusted, Login, Password, ConnectionTimeout);
            authDB.UpdateCredentials(testLogin, testPassword, updateLogin, updatePassword);
            Assert.True(authDB.CheckCredentials(updateLogin, updatePassword));

        }

        [Fact]
        public void TestDB2_DeleteCredentials()
        {
            AuthDatabaseUtils authDB = new AuthDatabaseUtils(Server, Database, IsTrusted, Login, Password, ConnectionTimeout);
            authDB.DeleteCredentials(updateLogin, updatePassword);
            Assert.False(authDB.CheckCredentials(updateLogin, updatePassword));

        }

        [Fact]
        public void TestDB2_UpdateCredentials_WhichAreNotExist()
        {
            AuthDatabaseUtils authDB = new AuthDatabaseUtils(Server, Database, IsTrusted, Login, Password, ConnectionTimeout);
            Assert.False(authDB.UpdateCredentials("neverExist", "nnn", updateLogin, updatePassword));
            

        }


       [Fact]
        public void TestDB2_DeleteCredentials_WhichAreNotExist()
        {
            AuthDatabaseUtils authDB = new AuthDatabaseUtils(Server, Database, IsTrusted, Login, Password, ConnectionTimeout);
            Assert.True(authDB.DeleteCredentials("neverExist", "nnn"));

        }

       [Fact]
        public void TestDB_AddCredentials_Null()
        {
            AuthDatabaseUtils authDB = new AuthDatabaseUtils(Server, Database, IsTrusted, Login, Password, ConnectionTimeout);
            // Assert.True(authDB.AddCredentials("wswwwwwww", testPassword));
            authDB.AddCredentials(null, null);
            Assert.False(authDB.CheckCredentials(null, null));

        }

        [Fact]
        public void TestDB_AddCredentials_Empty()
        {
            AuthDatabaseUtils authDB = new AuthDatabaseUtils(Server, Database, IsTrusted, Login, Password, ConnectionTimeout);
            // Assert.True(authDB.AddCredentials("wswwwwwww", testPassword));
            authDB.AddCredentials("", "");
            Assert.False(authDB.CheckCredentials("", ""));

        }


    }
}



