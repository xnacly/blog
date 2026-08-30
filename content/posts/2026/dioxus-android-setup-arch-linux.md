---
title: "(Dioxus) Android Dev Setup for Arch Linux"
summary: "The summary of hours of pain until I finally understood the android cli and Androids idiocracy"
date: 2026-08-30
tags:
    - android
    - archlinux
    - rust
---

![android](/android/android.png)

{{<callout type="Info - TL;DR">}}
Dioxus docs are a bit short for the android specific dev setup, so this is 50%
ranting about androids dev setup and 50% documenting said setup with a nix
flake automating it at the end.
{{</callout>}}

I moved to Bilbao and I am missing some features from the local public
transport applications. So, I thought: an Android app, its gonna be easy,
right? Java sucks, Google stinks, but how hard can it be? 

First I decided to investigate react native: Just to be quickly disgruntled by
the 15 configuration files and the .claude and AGENTS.md file generated upon
`bun create expo --template default@sdk-57`[^1], and finding out a native
module[^2]  needs to go through typescript->kotlin|java->rust or one uses
[jsi-rs](https://github.com/laptou/jsi-rs). The latter seems to at least
partially abstract over the former. 

[^1]: 
    expo even added a [\-\-no-agents-md](https://docs.expo.dev/more/create-expo/#--no-agents-md), but of course by default you get the clanker integrations
[^2]: 
    I intent to write the logic for routing, data [de]serialisation and the general navigation core in Rust

I decided to check out dioxus next, I heard good things and their examples and
documentation looked fairly comprehensive and clean, on the first `dx serve
--android`, I got a nice panic `Result::unwrap() on an Err value` in
[BuildRequest::start_android_sim](https://github.com/DioxusLabs/dioxus/blob/main/packages/cli/src/build/android.rs#L572-L576)
somehow the emulator doesnt exist but the dioxus check for it misses that and
the `panic` after checking if the android tools exist is therefore able to
happen. I also had some issues with dioxus not expanding tileds to `$HOME` and
thus not being able to find llvm. 

> If youre asking yourself or me why i have not used the AUR packages [Arch
> Wiki>Android>App dev](https://wiki.archlinux.org/title/Android#App_development)
> recommends? The short answer is always permission issues, the long answer is
> the packages reside in `/opt/android-{sdk,ndk}` and the sdk wants to edit
> itself, which it cant due to perms being 0755.

Below is the setup that fixed all my issues and got Dioxus targeting Android
working on Arch Linux (good luck to you that it also fixes your issues :#):

# Installing Dependencies

Install android studio first:

## Android studio

In the Android Studio SDK Manager, install:

- Android SDK
- Android SDK Command-line Tools
- NDK (Side by side)
- cmake

See [Dioxus Mobile
App>Android](https://dioxuslabs.com/learn/0.7/guides/platforms/mobile#android)
and [Android Studio](https://developer.android.com/studio/index.html)

## Rust targets

Then add rust targets:

```shell
rustup target add \
    aarch64-linux-android \
    armv7-linux-androideabi \
    i686-linux-android x86_64-linux-android
```

## Configuring shell and path

Then define (path ofc changing depending on install path):

```shell
export ANDROID_HOME=/home/teo/Android/Sdk
export ANDROID_SDK_ROOT=/home/teo/Android/Sdk
export ANDROID_NDK_HOME=/home/teo/Android/Sdk/ndk/30.0.16138531
```

Also add the platform tools and the emulator to your path:

```shell
export PATH="$PATH:$ANDROID_HOME/emulator"
export PATH="$PATH:$ANDROID_HOME/platform-tools"
export PATH="$PATH:$ANDROID_HOME/cmdline-tools/latest/bin"
```

## Configuring the Android emulator

By default there are no sdk packages installed required to "create" an
emulator, so we need to first install the SDK. I went with 37.0 here, which is
Android 17, because its latest and my android device runs it:

```shell
android sdk install \
    platform-tools \
    emulator \
    platforms/android-37.0 \
    system-images/android-37.0/google_apis/x86_64
```

Then we create an emulator (technically an android virtual device [AVD]):

```shell
# omitting --profile results in it being named medium_phone
android emulator create
```

## Starting the Android emulator

And then we can finally use it to actually start it:

```shell
android emulator start medium_phone
```

And thats just to make sure it works, now the official dioxus docs pick back up
and we can run:

```shell
dx serve --android
```

And see the emulator start up and our app boot

# Alternatively: A Nix flake

Putting it together into a nix flake:

```nix
{
  description = "Dioxus Android development environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs = { self, nixpkgs, rust-overlay }:
    let
      system = "x86_64-linux";

      pkgs = import nixpkgs {
        inherit system;
        overlays = [ rust-overlay.overlays.default ];
      };

      rust = pkgs.rust-bin.stable.latest.default.override {
        targets = [
          "aarch64-linux-android"
          "armv7-linux-androideabi"
          "i686-linux-android"
          "x86_64-linux-android"
        ];
      };
    in
    {
      devShells.${system}.default = pkgs.mkShell {
        packages = with pkgs; [
          rust
          android-tools
        ];

        shellHook = ''
          export ANDROID_HOME="$HOME/Android/Sdk"
          export ANDROID_SDK_ROOT="$ANDROID_HOME"
          export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/30.0.16138531"
          export PATH="$PATH:$ANDROID_HOME/emulator"
          export PATH="$PATH:$ANDROID_HOME/platform-tools"
          export PATH="$PATH:$ANDROID_HOME/cmdline-tools/latest/bin"
        '';
      };
    };
}
```

The issue being: android studio isnt (AFAIK) fully managed by the nix store;
meaning, things like creating android virtual devices are made outside of the
nix context and thus I decided to not make android studio subject to the nix
flake. Also please make sure to change the ndk path, since I have installed
version 30.0.16138531 and you maybe have not :)
