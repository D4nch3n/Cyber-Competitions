import java.util.*;
import java.io.*;
import java.lang.*;
public class Palindrome{
  public static boolean istPalindrom(char[] wort){
        char[] reverse = new char[wort.length];
        int index = wort.length - 1;
        for(int i = 0; i < wort.length; i++) {
          reverse[index] = wort[i];
          index--;
        }
        boolean palindrom = true;
        for(int i = 0; i < wort.length; i++) {
          if(wort[i] != reverse[i]) {
            palindrom = false;
          }
        }
        return palindrom;
  }
  public static void main(String[] args) throws Exception
  {
    File file = new File("partytrap.txt");
    Scanner s = new Scanner(file);
    String init = s.nextLine();
    String[] wordlist = init.split(", ");
    int count = 0;
    for(int i = 0; i < wordlist.length; i++) {
      if(istPalindrom(wordlist[i].toLowerCase().toCharArray()))
        count++;
    }
    System.out.println(count);
  }
}
