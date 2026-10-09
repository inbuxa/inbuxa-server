# inbuxa expressions and loops
#
# "vnd.inbuxa.expressions" adds "let" and "eval" with arithmetic,
# string functions and arrays. "vnd.inbuxa.while" adds loops. Both are
# inbuxa extensions to Sieve.

require ["variables", "editheader", "fileinto", "mailbox", "imap4flags",
         "vnd.inbuxa.expressions", "vnd.inbuxa.while"];

# Header fields are available as values: the display name of the sender,
# falling back to the address when the name is empty.
let "sender" "header.from.name";
if eval "is_empty(sender)" {
    let "sender" "header.from.addr";
}
addheader "X-Sender-Name" "${sender}";

let "recipients" "header.to:cc[*].addr[*]";
let "total" "count(recipients)";
let "shouting" "is_uppercase(header.subject)";

if eval "total > 3" {
    addflag "$ManyRecipients";
}

let "i" "0";
let "domains" "''";
while "i < total" {
    let "domain" "email_part(recipients[i], 'domain')";
    let "domains" "domains + domain + ' '";
    let "i" "i + 1";
}
addheader "X-Recipient-Domains" "${domains}";

if eval "shouting" {
    addflag "$Shouting";
    let "subject" "to_lowercase(header.subject)";
    deleteheader "Subject";
    addheader "Subject" "${subject}";
}

if eval "contains_ignore_case(header.subject, 'meeting')" {
    fileinto :create "Calendar";
}
