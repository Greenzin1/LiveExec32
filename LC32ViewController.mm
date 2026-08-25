#import <UIKit/UIKit.h>

extern "C" int LiveExec32_run(const char *execPath, const char *rootPath, const char *dyldPath);
extern "C" int extract_zip(const char *zip_path, const char *dest_dir);

@interface LC32ViewController : UIViewController <UIDocumentPickerDelegate>
@end

@implementation LC32ViewController {
    UITextView *_console;
    UITextField *_pathField;
    UIButton *_runButton;
    UIButton *_pickButton;
    UIButton *_pickIPAButton;
    UILabel *_statusLabel;
    dispatch_queue_t _emulatorQueue;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"LiveExec32";
    self.view.backgroundColor = [UIColor systemBackgroundColor];
    _emulatorQueue = dispatch_queue_create("com.liveexec.emulator", DISPATCH_QUEUE_SERIAL);

    UILabel *titleLabel = [[UILabel alloc] init];
    titleLabel.text = @"LiveExec32";
    titleLabel.font = [UIFont boldSystemFontOfSize:28];
    titleLabel.textAlignment = NSTextAlignmentCenter;
    titleLabel.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:titleLabel];

    UILabel *subtitleLabel = [[UILabel alloc] init];
    subtitleLabel.text = @"32-bit ARM Emulator (No JIT)";
    subtitleLabel.font = [UIFont systemFontOfSize:14];
    subtitleLabel.textColor = [UIColor secondaryLabelColor];
    subtitleLabel.textAlignment = NSTextAlignmentCenter;
    subtitleLabel.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:subtitleLabel];

    _statusLabel = [[UILabel alloc] init];
    _statusLabel.text = @"Ready";
    _statusLabel.font = [UIFont systemFontOfSize:13 weight:UIFontWeightMedium];
    _statusLabel.textColor = [UIColor systemGreenColor];
    _statusLabel.textAlignment = NSTextAlignmentCenter;
    _statusLabel.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:_statusLabel];

    _pathField = [[UITextField alloc] init];
    _pathField.placeholder = @"/var/mobile/.../binary32";
    _pathField.borderStyle = UITextBorderStyleRoundedRect;
    _pathField.font = [UIFont monospacedSystemFontOfSize:13 weight:UIFontWeightRegular];
    _pathField.autocapitalizationType = UITextAutocapitalizationTypeNone;
    _pathField.autocorrectionType = UITextAutocorrectionTypeNo;
    _pathField.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:_pathField];

    _pickButton = [UIButton buttonWithType:UIButtonTypeSystem];
    [_pickButton setTitle:@"Browse" forState:UIControlStateNormal];
    [_pickButton addTarget:self action:@selector(pickFile) forControlEvents:UIControlEventTouchUpInside];
    _pickButton.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:_pickButton];

    _pickIPAButton = [UIButton buttonWithType:UIButtonTypeSystem];
    [_pickIPAButton setTitle:@"Open .ipa" forState:UIControlStateNormal];
    [_pickIPAButton setTitleColor:[UIColor systemOrangeColor] forState:UIControlStateNormal];
    [_pickIPAButton addTarget:self action:@selector(pickIPA) forControlEvents:UIControlEventTouchUpInside];
    _pickIPAButton.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:_pickIPAButton];

    _runButton = [UIButton buttonWithType:UIButtonTypeSystem];
    [_runButton setTitle:@"Run" forState:UIControlStateNormal];
    _runButton.titleLabel.font = [UIFont boldSystemFontOfSize:17];
    _runButton.backgroundColor = [UIColor systemBlueColor];
    [_runButton setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    _runButton.layer.cornerRadius = 10;
    [_runButton addTarget:self action:@selector(runBinary) forControlEvents:UIControlEventTouchUpInside];
    _runButton.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:_runButton];

    _console = [[UITextView alloc] init];
    _console.editable = NO;
    _console.font = [UIFont monospacedSystemFontOfSize:12 weight:UIFontWeightRegular];
    _console.backgroundColor = [UIColor blackColor];
    _console.textColor = [UIColor greenColor];
    _console.layer.cornerRadius = 8;
    _console.translatesAutoresizingMaskIntoConstraints = NO;
    _console.text = @"LiveExec32 Console\n==================\nSelect a 32-bit ARM binary.\n";
    [self.view addSubview:_console];

    [NSLayoutConstraint activateConstraints:@[
        [titleLabel.topAnchor constraintEqualToAnchor:self.view.safeAreaLayoutGuide.topAnchor constant:16],
        [titleLabel.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor constant:16],
        [titleLabel.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor constant:-16],

        [subtitleLabel.topAnchor constraintEqualToAnchor:titleLabel.bottomAnchor constant:4],
        [subtitleLabel.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor constant:16],
        [subtitleLabel.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor constant:-16],

        [_statusLabel.topAnchor constraintEqualToAnchor:subtitleLabel.bottomAnchor constant:4],
        [_statusLabel.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor constant:16],
        [_statusLabel.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor constant:-16],

        [_pathField.topAnchor constraintEqualToAnchor:_statusLabel.bottomAnchor constant:16],
        [_pathField.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor constant:16],
        [_pathField.trailingAnchor constraintEqualToAnchor:_pickButton.leadingAnchor constant:-8],
        [_pathField.heightAnchor constraintEqualToConstant:36],

        [_pickButton.centerYAnchor constraintEqualToAnchor:_pathField.centerYAnchor],
        [_pickButton.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor constant:-16],
        [_pickButton.widthAnchor constraintEqualToConstant:70],

        [_pickIPAButton.topAnchor constraintEqualToAnchor:_pathField.bottomAnchor constant:8],
        [_pickIPAButton.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor constant:16],

        [_runButton.topAnchor constraintEqualToAnchor:_pickIPAButton.bottomAnchor constant:12],
        [_runButton.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor constant:16],
        [_runButton.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor constant:-16],
        [_runButton.heightAnchor constraintEqualToConstant:44],

        [_console.topAnchor constraintEqualToAnchor:_runButton.bottomAnchor constant:12],
        [_console.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor constant:12],
        [_console.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor constant:-12],
        [_console.bottomAnchor constraintEqualToAnchor:self.view.safeAreaLayoutGuide.bottomAnchor constant:-12],
    ]];
}

- (void)pickFile {
    UIDocumentPickerViewController *picker = [[UIDocumentPickerViewController alloc]
        initWithDocumentTypes:@[@"public.item"]
        inMode:UIDocumentPickerModeImport];
    picker.delegate = (id)self;
    picker.allowsMultipleSelection = NO;
    [self presentViewController:picker animated:YES completion:nil];
}

- (void)pickIPA {
    UIDocumentPickerViewController *picker = [[UIDocumentPickerViewController alloc]
        initWithDocumentTypes:@[@"com.apple.pkzip-archive", @"com.apple.zip-archive", @"public.item"]
        inMode:UIDocumentPickerModeImport];
    picker.delegate = (id)self;
    picker.allowsMultipleSelection = NO;
    [self presentViewController:picker animated:YES completion:nil];
}

- (void)handlePickedURL:(NSURL *)url {
    NSString *tmpDir = [NSTemporaryDirectory() stringByAppendingPathComponent:@"liveexec_pick"];
    [[NSFileManager defaultManager] removeItemAtPath:tmpDir error:nil];
    [[NSFileManager defaultManager] createDirectoryAtPath:tmpDir withIntermediateDirectories:YES attributes:nil error:nil];
    NSString *destPath = [tmpDir stringByAppendingPathComponent:url.lastPathComponent];
    NSError *err = nil;
    [[NSFileManager defaultManager] copyItemAtURL:url toURL:[NSURL fileURLWithPath:destPath] error:&err];
    if (err) {
        destPath = url.path;
    }
    _pathField.text = destPath;
    [self log:@"Selected: %@", destPath];

    if ([destPath.pathExtension.lowercaseString isEqualToString:@"ipa"]) {
        [self extractIPA:destPath];
    }
}

- (void)documentPicker:(UIDocumentPickerViewController *)controller didPickDocumentAtURL:(NSURL *)url {
    if (url) [self handlePickedURL:url];
}

- (void)documentPicker:(UIDocumentPickerViewController *)controller didPickDocumentsAtURLs:(NSArray<NSURL *> *)urls {
    if (urls.count > 0) [self handlePickedURL:urls.firstObject];
}

- (void)documentPickerWasCancelled:(UIDocumentPickerViewController *)controller {}

- (void)extractIPA:(NSString *)ipaPath {
    [self log:@"Extracting IPA: %@", ipaPath.lastPathComponent];

    dispatch_async(_emulatorQueue, ^{
        NSString *tmpDir = [NSTemporaryDirectory() stringByAppendingPathComponent:@"liveexec_ipa"];
        [[NSFileManager defaultManager] removeItemAtPath:tmpDir error:nil];
        [[NSFileManager defaultManager] createDirectoryAtPath:tmpDir withIntermediateDirectories:YES attributes:nil error:nil];

        int status = extract_zip([ipaPath UTF8String], [tmpDir UTF8String]);

        if (status != 0) {
            dispatch_async(dispatch_get_main_queue(), ^{
                [self log:@"Error: unzip failed with code %d", status];
            });
            return;
        }

        // Find .app directory
        NSString *payloadDir = [tmpDir stringByAppendingPathComponent:@"Payload"];
        NSArray *contents = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:payloadDir error:nil];
        NSString *appPath = nil;
        for (NSString *item in contents) {
            if ([item.pathExtension isEqualToString:@"app"]) {
                appPath = [payloadDir stringByAppendingPathComponent:item];
                break;
            }
        }

        if (!appPath) {
            dispatch_async(dispatch_get_main_queue(), ^{
                [self log:@"Error: No .app found in IPA"];
            });
            return;
        }

        // Find the main binary from Info.plist
        NSString *infoPlistPath = [appPath stringByAppendingPathComponent:@"Info.plist"];
        NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:infoPlistPath];
        NSString *execName = info[@"CFBundleExecutable"];
        if (!execName) execName = info[@"CFBundleName"];

        if (execName) {
            NSString *execPath = [appPath stringByAppendingPathComponent:execName];
            if ([[NSFileManager defaultManager] fileExistsAtPath:execPath]) {
                dispatch_async(dispatch_get_main_queue(), ^{
                    self->_pathField.text = execPath;
                    [self log:@"Found binary: %@", execPath];
                    [self log:@"App: %@", info[@"CFBundleName"] ?: execName];
                });
                return;
            }
        }

        // Fallback: find first Mach-O
        NSArray *appContents = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:appPath error:nil];
        for (NSString *item in appContents) {
            if (![item.pathExtension isEqualToString:@"dylib"] &&
                ![item.pathExtension isEqualToString:@"plist"] &&
                ![item.pathExtension isEqualToString:@"nib"] &&
                ![item.pathExtension isEqualToString:@"storyboardc"]) {
                NSString *itemPath = [appPath stringByAppendingPathComponent:item];
                NSDictionary *attrs = [[NSFileManager defaultManager] attributesOfItemAtPath:itemPath error:nil];
                if (attrs[NSFileType] == NSFileTypeRegular) {
                    unsigned char header[4] = {0};
                    FILE *f = fopen([itemPath UTF8String], "r");
                    if (f) {
                        fread(header, 1, 4, f);
                        fclose(f);
                        // Mach-O magic: FEEDFACE or BEBAFECA (FAT)
                        uint32_t magic = *(uint32_t *)header;
                        if (magic == 0xFEEDFACE || magic == 0xBEBAFECA || magic == 0xCAFEBABE) {
                            dispatch_async(dispatch_get_main_queue(), ^{
                                self->_pathField.text = itemPath;
                                [self log:@"Found Mach-O: %@", itemPath];
                            });
                            return;
                        }
                    }
                }
            }
        }

        dispatch_async(dispatch_get_main_queue(), ^{
            [self log:@"Error: No executable found in %@", appPath];
            [self log:@"Contents: %@", [appContents componentsJoinedByString:@", "]];
        });
    });
}

- (void)log:(NSString *)fmt, ... {
    va_list args;
    va_start(args, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:args];
    va_end(args);
    dispatch_async(dispatch_get_main_queue(), ^{
        self->_console.text = [self->_console.text stringByAppendingFormat:@"%@\n", msg];
        [self->_console scrollRangeToVisible:NSMakeRange(self->_console.text.length, 0)];
    });
}

- (void)runBinary {
    NSString *path = _pathField.text;
    if (path.length == 0) {
        [self log:@"Error: No path specified"];
        return;
    }

    _runButton.enabled = NO;
    [_runButton setTitle:@"Running..." forState:UIControlStateNormal];
    _statusLabel.text = @"Running...";
    _statusLabel.textColor = [UIColor systemOrangeColor];

    const char *cPath = [path UTF8String];
    NSString *bundlePath = [[NSBundle mainBundle] bundlePath];
    NSString *ramdiskPath = [bundlePath stringByAppendingPathComponent:@"ramdisk32"];
    const char *rootPath = [ramdiskPath UTF8String];
    NSString *dyldPathStr = [ramdiskPath stringByAppendingPathComponent:@"usr/lib/dyld"];
    const char *dyldPath = [dyldPathStr UTF8String];
    dispatch_async(_emulatorQueue, ^{
        [self log:@"Loading: %s", cPath];
        [self log:@"Root: %s", rootPath];
        [self log:@"Dyld: %s", dyldPath];
        int result = LiveExec32_run(cPath, rootPath, dyldPath);
        dispatch_async(dispatch_get_main_queue(), ^{
            self->_runButton.enabled = YES;
            [self->_runButton setTitle:@"Run" forState:UIControlStateNormal];
            self->_statusLabel.text = [NSString stringWithFormat:@"Exited with code %d", result];
            self->_statusLabel.textColor = result == 0 ? [UIColor systemGreenColor] : [UIColor systemRedColor];
        });
    });
}

- (UIStatusBarStyle)preferredStatusBarStyle {
    return UIStatusBarStyleLightContent;
}

@end
