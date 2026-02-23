// Language Switcher for MOT Content Generator
// Supports Myanmar (my) and English (en) languages

// Language translations object
const translations = {
  // Navigation and Layout
  'Genius AutoWriter': {
    my: 'Genius AutoWriter',
  },
  'Change API Key': {
    my: 'API key ပြောင်းရန်',
    en: 'Change API Key',
  },
  'Content Generator': {
    my: 'Content Generator',
    en: 'Content Generator',
  },
  Dashboard: {
    my: 'စာမျက်နှာများ',
    en: 'Dashboard',
  },
  Users: {
    my: 'အသုံးပြုသူများ',
    en: 'Users',
  },
  Generator: {
    my: 'Content ဖန်တီးရန်',
    en: 'Generator',
  },
  'Text Input': {
    my: 'စာသား',
    en: 'Text Input',
  },
  Logout: {
    my: 'ထွက်ရန်',
    en: 'Logout',
  },
  Administrator: {
    my: 'စီမံခန့်ခွဲသူ',
    en: 'Administrator',
  },
  'Content Creator': {
    my: 'Content ရေးသားသူ',
    en: 'Content Creator',
  },

  // Content Generation Form
  'Content Generation Form': {
    my: 'Content ဖန်တီးရေးသားရန်နေရာ',
    en: 'Content Generation Form',
  },
  'Content Details Form': {
    my: 'Content အသေးစိတ် ဖောင်',
    en: 'Content Details Form',
  },
  'Fill in the details below': {
    my: 'အောက်ပါအချက်အလက်များကို ဖြည့်သွင်းပါ',
    en: 'Fill in the details below',
  },
  'Provide the details for the content you want to generate.': {
    my: 'ဖန်တီးလိုသော Content အတွက် အသေးစိတ်အချက်အလက်များ ဖြည့်ပေးပါ။',
    en: 'Provide the details for the content you want to generate.',
  },
  'Content Creation': {
    my: 'Content ဖန်တီးခြင်း',
    en: 'Content Creation',
  },
  'Content Title': {
    my: 'Content ခေါင်းစဉ်',
    en: 'Content Title',
  },
  Topic: {
    my: 'Content ၏ အဓိကအကြောင်းအရာ',
    en: 'Topic',
  },
  Purpose: {
    my: 'ရည်ရွယ်ချက်',
    en: 'Purpose',
  },
  'Select the purpose': {
    my: 'Content ရည်ရွယ်ချက်ကိုရွေးပါ',
    en: 'Select the purpose',
  },
  'Informative Content': {
    my: 'အသုံးဝင်သတင်း/ အချက်အလက်ပေးခြင်း',
    en: 'Providing Useful News/Information',
  },
  'Audience Engagement': {
    my: 'Audience တုံ့ပြန်မှုဖော်ခြင်း/ Engagement တိုးခြင်း',
    en: 'Generating Audience Engagement/ Response',
  },
  'Product/Service Sales': {
    my: 'Product/Service ရောင်းချခြင်း',
    en: 'Selling Products/Services',
  },
  'Emotional Content': {
    my: 'ခံစားမှုဖန်တီးခြင်း',
    en: 'Creating a Feeling/Emotion',
  },
  'Event/Update Announcement': {
    my: 'Event ကြေညာခြင်း',
    en: 'Announcing an Event',
  },
  'Educational Content': {
    my: 'သင်ခန်းစာပေးခြင်း',
    en: 'Giving Educational Tutorial',
  },
  'Product Feature Showcase': {
    my: 'Product feature ပြခြင်း',
    en: 'Showing Product Feature/Showcase',
  },
  Audience: {
    my: 'ပရိသတ်',
    en: 'Audience',
  },
  'Target Audience': {
    my: 'ပစ်မှတ်ထားသော သုံးစွဲသူအုပ်စု',
    en: 'Target Audience',
  },
  'Output Language': {
    my: 'ထွက်လာမည့်ဘာသာစကား',
    en: 'Output Language',
  },
  'Writing Style': {
    my: 'ရေးသားပုံစံ',
    en: 'Writing Style',
  },
  'Writing Style / Tone': {
    my: 'စာရေးပုံစံ / အသံ ပုံစံ',
    en: 'Writing Style / Tone',
  },
  'Select Writing Style': {
    my: 'ရေးသားပုံစံရွေးပါ',
    en: 'Select Writing Style',
  },
  'Select the writing style or tone': {
    my: 'စာရေးပုံစံ (သို့) အသံ ပုံစံကို ရွေးချယ်ပါ',
    en: 'Select the writing style or tone',
  },
  'Word Count': {
    my: 'စာလုံးအရေအတွက်',
    en: 'Word Count',
  },
  'Content Length': {
    my: 'အကြောင်းအရာ အရှည်',
    en: 'Content Length',
  },
  'Select content length': {
    my: 'Content Length ကိုရွေးချယ်ပါ',
    en: 'Select content length',
  },
  'Select output language': {
    my: 'Output Language ကိုရွေးချယ်ပါ',
    en: 'Select output language',
  },
  Keywords: {
    my: 'အဓိကစကားလုံးများ',
    en: 'Keywords',
  },
  Hashtags: {
    my: 'Hashtags',
    en: 'Hashtags',
  },
  'Call to Action (CTA)': {
    my: 'လုပ်ဆောင်ရန်တောင်းဆိုချက် (CTA)',
    en: 'Call to Action (CTA)',
  },
  'Negative Constraints': {
    my: 'တားမြစ်ချက်များ',
    en: 'Negative Constraints',
  },
  'Include Emojis': {
    my: 'Emojis ထည့်မှာလား',
    en: 'Include Emojis',
  },
  'Generate Content': {
    my: 'Content ဖန်တီးပါ',
    en: 'Generate Content',
  },
  'Save Content': {
    my: 'Content သိမ်းဆည်းမည်',
    en: 'Save Content',
  },
  Copy: {
    my: 'ကူးယူမည်',
    en: 'Copy',
  },
  'Copied!': {
    my: 'ကူးပြီးပါပြီ!',
    en: 'Copied!',
  },
  Close: {
    my: 'ပိတ်မည်',
    en: 'Close',
  },
  'Saving...': {
    my: 'သိမ်းနေသည်...',
    en: 'Saving...',
  },
  Save: {
    my: 'သိမ်းဆည်းမည်',
    en: 'Save',
  },
  Change: {
    my: 'ပြောင်းရန်',
    en: 'Change',
  },

  // Error Messages
  'Your subscription period has ended. Please contact admin for renewal.': {
    my: 'သင်၏ subscription period ကုန်ဆုံးသွားပါပြီ။ သက်တမ်းတိုးရန် ကျေးဇူးပြု၍ admin ကို ဆက်သွယ်ပါ။',
    en: 'Your subscription period has ended. Please contact admin for renewal.',
  },
  'Your subscription period has ended': {
    my: 'သင်၏ subscription period ကုန်ဆုံးသွားပါပြီ',
    en: 'Your subscription period has ended',
  },
  'Your account is expired': {
    my: 'သင်၏ account သက်တမ်းကုန်ဆုံးသွားပါပြီ',
    en: 'Your account is expired',
  },

  // Form Options
  'None (General)': {
    my: 'မရွေးချယ် (ယေဘုယျ)',
    en: 'None (General)',
  },
  'မြန်မာ (Myanmar)': {
    my: 'မြန်မာ (Myanmar)',
    en: 'Myanmar (Burmese)',
  },
  'Myanmar (မြန်မာ)': {
    my: 'မြန်မာ (Myanmar)',
    en: 'Myanmar (မြန်မာ)',
  },
  'English (အင်္ဂလိပ်)': {
    my: 'အင်္ဂလိပ် (English)',
    en: 'English',
  },
  Myanmar: {
    my: 'မြန်မာ',
    en: 'Myanmar',
  },
  English: {
    my: 'အင်္ဂလိပ်',
    en: 'English',
  },

  // Buttons and Actions
  'Add Link': {
    my: 'လင့်ထည့်ရန်',
    en: 'Add Link',
  },
  ON: {
    my: 'ဖွင့်',
    en: 'ON',
  },
  OFF: {
    my: 'ပိတ်',
    en: 'OFF',
  },

  // Messages and Notifications
  'Content generated successfully!': {
    my: 'Content ကို အောင်မြင်စွာ ဖန်တီးပြီးပါပြီ!',
    en: 'Content generated successfully!',
  },
  'Content saved successfully!': {
    my: 'Content ကို အောင်မြင်စွာ သိမ်းဆည်းပြီးပါပြီ!',
    en: 'Content saved successfully!',
  },
  Success: {
    my: 'အောင်မြင်',
    en: 'Success',
  },
  Saved: {
    my: 'သိမ်းဆည်းပြီး',
    en: 'Saved',
  },

  // Login Form
  'Login to Your Account': {
    my: 'သင့်အကောင့်သို့ ဝင်ရောက်ပါ',
    en: 'Login to Your Account',
  },
  'Email Address': {
    my: 'အီးမေးလ်လိပ်စာ',
    en: 'Email Address',
  },
  Password: {
    my: 'စကားဝှက်',
    en: 'Password',
  },
  'Gemini API Key': {
    my: 'Gemini API Key',
    en: 'Gemini API Key',
  },
  Login: {
    my: 'လော့ဂ်အင်ဝင်မယ်',
    en: 'Login',
  },
  'Logging in...': {
    my: 'လော့ဂ်အင်ဝင်နေသည်...',
    en: 'Logging in...',
  },
  'Remember me': {
    my: 'မှတ်ထားပါ',
    en: 'Remember me',
  },
  Update: {
    my: 'ပြင်ဆင်မည်',
    en: 'Update',
  },
  'Updating...': {
    my: 'ပြင်ဆင်နေသည်...',
    en: 'Updating...',
  },
  Create: {
    my: 'ဖန်တီးမည်',
    en: 'Create',
  },
  'Creating...': {
    my: 'ဖန်တီးနေသည်...',
    en: 'Creating...',
  },

  // Placeholders
  'Page ၏ အမည် သို့မဟုတ် Brand အမည်': {
    my: 'Page ၏ အမည် သို့မဟုတ် Brand အမည်',
    en: 'Page name or Brand name',
  },
  'Enter content title': {
    my: 'Content ခေါင်းစဉ် ထည့်ပါ',
    en: 'Enter content title',
  },
  'ဒီနေရာတွင် content ၏ အဓိက အကြောင်းအရာကို ရေးပါ': {
    my: 'ဒီနေရာတွင် content ၏ အဓိက အကြောင်းအရာကို ရေးပါ',
    en: 'Enter the main topic of your content here',
  },
  'Write the main topic or draft idea of your content here': {
    my: 'ဒီနေရာတွင် Content ၏ အဓိကအကြောင်းအရာ သို့မဟုတ် Idea အကြမ်းဖျင်းကို ရေးပါ',
    en: 'Write the main topic or draft idea of your content here',
  },
  'e.g. Young adults aged 20-30': {
    my: 'ဥပမာ - အသက် ၂၀ မှ ၃၀ ကြား လူငယ်များ',
    en: 'e.g. Young adults aged 20-30',
  },
  'e.g. #DigitalMarketing #OnlineBusiness': {
    my: 'ဥပမာ - #DigitalMarketing #OnlineBusiness',
    en: 'e.g. #DigitalMarketing #OnlineBusiness',
  },
  'e.g. Do not mention price, avoid offensive words': {
    my: 'ဥပမာ - စျေးနှုန်းကို မဖော်ပြပါနဲ့၊ ရိုင်းစိုင်းသော စကားလုံးများကို ရှောင်ပါ',
    en: 'e.g. Do not mention price, avoid offensive words',
  },
  'ဥပမာ - ပညာပေးရန်၊ Engagement ရရှိရန်၊ ရောင်းအားမြှင့်တင်ရန်': {
    my: 'ဥပမာ - ပညာပေးရန်၊ Engagement ရရှိရန်၊ ရောင်းအားမြှင့်တင်ရန်',
    en: 'Example - To educate, Get engagement, Boost sales',
  },
  'ဥပမာ - အသက် ၂၀ မှ ၃၀ ကြား လူငယ်တွေ': {
    my: 'ဥပမာ - အသက် ၂၀ မှ ၃၀ ကြား လူငယ်တွေ',
    en: 'Example - Young people aged 20 to 30',
  },
  'ဥပမာ - ၁၀၀ မှ ၅၀၀ စကားလုံး': {
    my: 'ဥပမာ - ၁၀၀ မှ ၅၀၀ စကားလုံး',
    en: 'Example - 100 to 500 words',
  },
  'ဥပမာ - အစားအသောက်၊ ကျန်းမာရေး၊ နည်းပညာ': {
    my: 'ဥပမာ - အစားအသောက်၊ ကျန်းမာရေး၊ နည်းပညာ',
    en: 'Example - Food, Health, Technology',
  },
  'ဥပမာ - #အစားအစာ #ကျန်းမာရေး #မြန်မာ': {
    my: 'ဥပမာ - #အစားအစာ #ကျန်းမာရေး #မြန်မာ',
    en: 'Example - #food #healthy #myanmar',
  },
  'ဥပမာ - ယခုပင် မှာယူပါ၊ ဆက်သွယ်ပါ၊ ကြည့်ရှုပါ': {
    my: 'ဥပမာ - ယခုပင် မှာယူပါ၊ ဆက်သွယ်ပါ၊ ကြည့်ရှုပါ',
    en: 'Example - Order now, Contact us, Watch now',
  },
  'မပါဝင်စေလိုသော စကားလုံးများ သို့မဟုတ် အကြောင်းအရာများ': {
    my: 'မပါဝင်စေလိုသော စကားလုံးများ သို့မဟုတ် အကြောင်းအရာများ',
    en: 'Words or topics you want to avoid',
  },
  'Website URL ထည့်ပါ': {
    my: 'Website URL ထည့်ပါ',
    en: 'Enter website URL',
  },
  'Generated content will appear here...': {
    my: 'ဖန်တီးထားသော content ကို ဒီနေရာမှာ ပြပါမယ်...',
    en: 'Generated content will appear here...',
  },
  'ရွေးချယ်ပါ...': {
    my: 'ရွေးချယ်ပါ...',
    en: 'Select...',
  },
  'Select...': {
    my: 'ရွေးချယ်ပါ...',
    en: 'Select...',
  },

  // Additional UI Text
  'Content မှာ emoji တွေ ထည့်မလား မထည့်မလား': {
    my: 'Content မှာ emoji တွေ ထည့်မလား မထည့်မလား',
    en: 'Whether to include emojis in content or not',
  },

  // Form Labels and Options
  'Keywords (separate keywords with commas)': {
    my: 'အဓိကစကားလုံးများ (ကော်မာဖြင့် ပိုင်းခြားပါ)',
    en: 'Keywords (separate keywords with commas)',
  },
  Hashtags: {
    my: 'Hashtags',
    en: 'Hashtags',
  },
  'Call to Action (CTA)': {
    my: 'လုပ်ဆောင်ရန်တောင်းဆိုချက် (CTA)',
    en: 'Call to Action (CTA)',
  },
  'Negative Constraints': {
    my: 'မပါဝင်စေလိုသောအရာများ',
    en: 'Negative Constraints',
  },
  'Upload an image (Optional):': {
    my: 'ပုံတစ်ပုံ ထည့်ပါ (မဖြစ်မနေ မလိုအပ်ပါ):',
    en: 'Upload an image (Optional):',
  },
  'Upload Image': {
    my: 'ပုံတင်ရန်',
    en: 'Upload Image',
  },
  'Drop your images here, or browse': {
    my: 'Drop your images here, or browse',
    en: 'Drop your images here, or browse',
  },
  'Supports: JPG, JPEG2000, PNG': {
    my: 'Supports: JPG, JPEG2000, PNG',
    en: 'Supports: JPG, JPEG2000, PNG',
  },
  'You can add the hashtags.': {
    my: 'ပါဝင်စေချင်သော Hashtags များကိုထည့်ပါ',
    en: 'You can add the hashtags.',
  },
  'Things that content should not include.': {
    my: 'Content ထဲမှာ ပါဝင်စေချင်မသော အကြောင်းအရာများ ဖော်ပြပါ',
    en: 'Things that content should not include.',
  },
  'Generated Content:': {
    my: 'ဖန်တီးထားသော Content:',
    en: 'Generated Content:',
  },
  'Generated Content': {
    my: 'ဖန်တီးပြီးသော Content',
    en: 'Generated Content',
  },
  'Review and edit your generated content here.': {
    my: 'ဖန်တီးထားသော Content ကို ဦးစွာ ကြည့်ပြီး ပြင်ဆင်နိုင်ပါသည်။',
    en: 'Review and edit your generated content here.',
  },
  'Fill out the form to generate your content.': {
    my: 'ဖောင်ကို ဖြည့်ပြီး Content ဖန်တီးပါ။',
    en: 'Fill out the form to generate your content.',
  },
  'Your content will appear here.': {
    my: 'သင်၏ ဖန်တီးထားသော Content သည် ဤနေရာတွင် ပေါ်လာမည်။',
    en: 'Your content will appear here.',
  },
  'View My Contents': {
    my: 'Content ကြည့်ရန်',
    en: 'View My Contents',
  },

  // Toggle States
  ON: {
    my: 'ဖွင့်',
    en: 'ON',
  },
  OFF: {
    my: 'ပိတ်',
    en: 'OFF',
  },

  // Dashboard Elements
  'Content Generator': {
    my: 'Content Generator',
    en: 'Content Generator',
  },
  'Create content with advanced customization': {
    my: 'အဆင့်မြင့် customization ဖြင့် content ဖန်တီးပါ',
    en: 'Create content with advanced customization',
  },
  'Total Contents': {
    my: 'စုစုပေါင်း Content များ',
    en: 'Total Contents',
  },
  'Remaining Contents': {
    my: 'ကျန်ရှိသော Content များ',
    en: 'Remaining Contents',
  },
  'Unlimited Contents': {
    my: 'အကန့်အသတ်မရှိ Contents',
    en: 'Unlimited Contents',
  },
  'Account Expires': {
    my: 'အကောင့်သက်တမ်းကုန်ရက်',
    en: 'Account Expires',
  },
  'Recent Content': {
    my: 'လတ်တလော Content များ',
    en: 'Recent Content',
  },
  'View All': {
    my: 'အားလုံးကြည့်ရန်',
    en: 'View All',
  },

  // Dashboard Page Elements
  'My Contents': {
    my: 'ကျွန်ုပ်၏ Content များ',
    en: 'My Contents',
  },
  'Manage all your created content': {
    my: 'သင်ဖန်တီးထားသော content အားလုံးကို စီမံခန့်ခွဲပါ',
    en: 'Manage all your created content',
  },

  // Content Library Elements
  'Content Library': {
    my: 'Content စာကြည့်တိုက်',
    en: 'Content Library',
  },
  'Total:': {
    my: 'စုစုပေါင်း:',
    en: 'Total:',
  },
  Title: {
    my: 'ခေါင်းစဉ်',
    en: 'Title',
  },
  Purpose: {
    my: 'ရည်ရွယ်ချက်',
    en: 'Purpose',
  },
  Created: {
    my: 'ဖန်တီးသည့်ရက်',
    en: 'Created',
  },
  Updated: {
    my: 'ပြင်ဆင်သည့်ရက်',
    en: 'Updated',
  },
  Actions: {
    my: 'လုပ်ဆောင်ချက်များ',
    en: 'Actions',
  },

  // Action Buttons
  View: {
    my: 'ကြည့်ရန်',
    en: 'View',
  },
  Edit: {
    my: 'ပြင်ဆင်ရန်',
    en: 'Edit',
  },
  Delete: {
    my: 'ဖျက်မည်',
    en: 'Delete',
  },

  // Delete Modal
  'Delete Content': {
    my: 'Content ဖျက်ရန်',
    en: 'Delete Content',
  },
  'Are you sure you want to delete this content? This action cannot be undone.': {
    my: 'ဒီ content ကို ဖျက်ချင်တာ သေချာပါသလား? ဒီလုပ်ဆောင်ချက်ကို ပြန်ပြင်လို့ မရပါဘူး။',
    en: 'Are you sure you want to delete this content? This action cannot be undone.',
  },
  'Cancel Delete': {
    my: 'မဖျက်တော့ပါ',
    en: 'Cancel',
  },
  Cancel: {
    my: 'မပြင်ဆင်တော့ပါ',
    en: 'Cancel',
  },

  // Edit Content Page
  'Edit Content': {
    my: 'Content ပြင်ဆင်ခြင်း',
    en: 'Edit Content',
  },
  'Update your content details': {
    my: 'Content ၏ အသေးစိတ်များကို ပြင်ဆင်ပါ',
    en: 'Update your content details',
  },
  'Update your content details below': {
    my: 'Content ၏ အသေးစိတ်များကို ပြင်ဆင်ပါ',
    en: 'Update your content details below',
  },
  Content: {
    my: 'Content',
    en: 'Content',
  },
  Update: {
    my: 'ပြင်ဆင်မည်',
    en: 'Update',
  },
  'Update Content': {
    my: 'Content ပြင်ဆင်ရန်',
    en: 'Update Content',
  },

  // View Content Page
  'Not specified': {
    my: 'မသတ်မှတ်ထားပါ',
    en: 'Not specified',
  },
  'Copy Content': {
    my: 'Content ကူးယူရန်',
    en: 'Copy Content',
  },
  'Writing Style': {
    my: 'စာရေးပုံစံ',
    en: 'Writing Style',
  },
  Keywords: {
    my: 'အဓိကစကားလုံးများ',
    en: 'Keywords',
  },

  // Toast Messages
  'Content saved successfully!': {
    my: 'Content ကို အောင်မြင်စွာ သိမ်းဆည်းပြီးပါပြီ!',
    en: 'Content saved successfully!',
  },
  'Content updated successfully!': {
    my: 'Content ကို အောင်မြင်စွာ ပြင်ဆင်ပြီးပါပြီ!',
    en: 'Content updated successfully!',
  },
  'Content deleted successfully!': {
    my: 'Content ကို အောင်မြင်စွာ ဖျက်ပြီးပါပြီ!',
    en: 'Content deleted successfully!',
  },
  'Content copied to clipboard!': {
    my: 'Content ကို clipboard သို့ ကူးယူပြီးပါပြီ!',
    en: 'Content copied to clipboard!',
  },
  'Failed to copy content': {
    my: 'Content ကူးယူ၍ မရပါ',
    en: 'Failed to copy content',
  },
  'Error generating content. Please try again.': {
    my: 'Content ဖန်တီးရာတွင် အမှားရှိပါသည်။ ကျေးဇူးပြု၍ ထပ်မံကြိုးစားပါ။',
    en: 'Error generating content. Please try again.',
  },
  'Please fill in all required fields.': {
    my: 'လိုအပ်သော အကွက်များအားလုံးကို ဖြည့်စွက်ပါ။',
    en: 'Please fill in all required fields.',
  },
  'Login successful!': {
    my: 'အောင်မြင်စွာ ဝင်ရောက်ပြီးပါပြီ!',
    en: 'Login successful!',
  },
  'Invalid credentials. Please try again.': {
    my: 'အထောက်အထား မှားယွင်းနေပါသည်။ ကျေးဇူးပြု၍ ထပ်မံကြိုးစားပါ။',
    en: 'Invalid credentials. Please try again.',
  },

  // Login Page
  'Welcome Back': {
    my: 'ပြန်လည်ကြိုဆိုပါတယ်',
    en: 'Welcome Back',
  },
  'Genius Autowriter': {
    my: 'Genius Autowriter',
    en: 'Genius Autowriter',
  },
  'Sign in to your Genius AutoWriter account': {
    my: 'သင့် Genius AutoWriter အကောင့်သို့ ဝင်ရောက်ပါ',
    en: 'Sign in to your Genius AutoWriter account',
  },
  Email: {
    my: 'အီးမေးလ်',
    en: 'Email',
  },
  Password: {
    my: 'စကားဝှက်',
    en: 'Password',
  },
  'API Key': {
    my: 'API Key',
    en: 'API Key',
  },
  'Sign In': {
    my: 'ဝင်ရောက်ရန်',
    en: 'Sign In',
  },

  // Error Messages
  'Password cannot contain spaces': {
    my: 'စကားဝှက်တွင် space မပါရပါ',
    en: 'Password cannot contain spaces',
  },
  'Please use a Gmail address (@gmail.com)': {
    my: 'Gmail လိပ်စာကို အသုံးပြုပါ (@gmail.com)',
    en: 'Please use a Gmail address (@gmail.com)',
  },

  // Placeholders
  'Enter your email': {
    my: 'သင့်အီးမေးလ် ရိုက်ထည့်ပါ',
    en: 'Enter your email',
  },
  'Enter your password': {
    my: 'သင့်စကားဝှက် ရိုက်ထည့်ပါ',
    en: 'Enter your password',
  },

  'Enter Gemini API Key': {
    my: 'Gemini API Key ရိုက်ထည့်ပါ',
    en: 'Enter Gemini API Key',
  },

  // Word Count Options
  'Word Count': {
    my: 'စာလုံးအရေအတွက်',
    en: 'Word Count',
  },
  Short: {
    my: 'အတို',
    en: 'Short',
  },
  Medium: {
    my: 'အလယ်အလတ်',
    en: 'Medium',
  },
  Long: {
    my: 'အရှည်',
    en: 'Long',
  },

  // Generate Button States
  'Generate Content': {
    my: 'Content ဖန်တီးမည်',
    en: 'Generate Content',
  },
  'Generating content...': {
    my: 'Content ဖန်တီးနေသည်...',
    en: 'Generating content...',
  },
  'Generating your content...': {
    my: 'မိတ်ဆွေရဲ့ Content ကို ဖန်တီးနေပါတယ်...',
    en: 'Generating your content...',
  },
  'Please wait a moment': {
    my: 'ကျေးဇူးပြုပြီး ခဏစောင့်ပေးပါ',
    en: 'Please wait a moment',
  },
  'Saving...': {
    my: 'သိမ်းနေသည်...',
    en: 'Saving...',
  },

  // Save Content Modal
  'Save Content': {
    my: 'Content သိမ်းဆည်းရန်',
    en: 'Save Content',
  },
  'Enter a title for this content:': {
    my: 'ဒီ content အတွက် ခေါင်းစဉ် ထည့်ပါ:',
    en: 'Enter a title for this content:',
  },
  OK: {
    my: 'အိုကေ',
    en: 'OK',
  },

  // Writing Styles
  'Promotional / Sales-Oriented Style': {
    my: 'အရောင်းမြှင့်တင်ရေး ပုံစံ',
    en: 'Promotional / Sales-Oriented Style',
  },
  'Conversational / Interactive Style': {
    my: 'စကားပြောပုံစံ',
    en: 'Conversational / Interactive Style',
  },
  'Informational / Educational Style': {
    my: 'ပညာပေး/အသိပေး ပုံစံ',
    en: 'Informational / Educational Style',
  },
  'Storytelling / Inspirational Style': {
    my: 'ဇာတ်လမ်းပြောပြခြင်း ပုံစံ',
    en: 'Storytelling / Inspirational Style',
  },
  'Casual / Humorous Style': {
    my: 'ပေါ့ပေါ့ပါးပါး ပုံစံ',
    en: 'Casual / Humorous Style',
  },

  // Footer Text
  'Powered by Myanmar Online Technology': {
    my: 'Myanmar Online Technology မှ ပံ့ပိုးထားသည်',
    en: 'Powered by Myanmar Online Technology',
  },

  // Admin Login
  'Admin Login': {
    my: 'Admin ဝင်ရောက်ရန်',
    en: 'Admin Login',
  },
  'Sign in to admin panel': {
    my: 'Admin panel သို့ ဝင်ရောက်ပါ',
    en: 'Sign in to admin panel',
  },

  // Voice Generator Specific
  'Voice Content Generator': {
    my: 'အသံဖြင့် Content ဖန်တီးခြင်း',
    en: 'Voice Content Generator',
  },
  'Generator With Voice': {
    my: 'အသံဖြင့် ဖန်တီးခြင်း',
    en: 'Generator With Voice',
  },
  'Voice Input': {
    my: 'အသံထည့်သွင်းမှု',
    en: 'Voice Input',
  },
  'Create content using voice input and images': {
    my: 'အသံနဲ့ ပုံတွေ သုံးပြီး content ဖန်တီးပါ',
    en: 'Create content using voice input and images',
  },
  'Record your voice for content generation': {
    my: 'အကြောင်းအရာ ဖန်တီးရန် သင့်အသံကို သွင်းပါ',
    en: 'Record your voice for content generation',
  },
  'Start Recording': {
    my: 'အသံသွင်းချင်း စတင်ပါ',
    en: 'Start Recording',
  },
  'Stop Recording': {
    my: 'အသံသွင်းခြင်း ရပ်ပါ',
    en: 'Stop Recording',
  },
  'Recording...': {
    my: 'အသံသွင်းနေသည်...',
    en: 'Recording...',
  },
  'Voice recording saved successfully!': {
    my: 'အသံသွင်းခြင်းကို အောင်မြင်စွာ သိမ်းဆည်းပြီးပါပြီ!',
    en: 'Voice recording saved successfully!',
  },
  'Voice recording saved successfully! Ready for content generation.': {
    my: 'အသံသွင်းခြင်းကို အောင်မြင်စွာ သိမ်းဆည်းပြီးပါပြီ! Content ဖန်တီးရန် အဆင်သင့်ဖြစ်ပါပြီ။',
    en: 'Voice recording saved successfully! Ready for content generation.',
  },
  'Image (Optional)': {
    my: 'ပုံ (မဖြစ်မနေ မလိုအပ်ပါ)',
    en: 'Image (Optional)',
  },
  'Upload Image': {
    my: 'ပုံတင်ရန်',
    en: 'Upload Image',
  },
  'Take Photo': {
    my: 'ဓာတ်ပုံရိုက်ရန်',
    en: 'Take Photo',
  },
  'Open Camera': {
    my: 'ကင်မရာဖွင့်ရန်',
    en: 'Open Camera',
  },
  'Capture Photo': {
    my: 'ဓာတ်ပုံရိုက်ရန်',
    en: 'Capture Photo',
  },
  Cancel: {
    my: 'မပြင်ဆင်တော့ပါ',
    en: 'Cancel',
  },
  Voice: {
    my: 'အသံ',
    en: 'Voice',
  },
  'Generate Content': {
    my: 'Content ဖန်တီးမည်',
    en: 'Generate Content',
  },
  'Save Content': {
    my: 'Content သိမ်းဆည်းရန်',
    en: 'Save Content',
  },
  'Recent Content': {
    my: 'လတ်တလော Content များ',
    en: 'Recent Content',
  },
  'No content created yet. Generate your first content above!': {
    my: 'Content မရှိသေးပါ။ အပေါ်မှာ သင့်ရဲ့ ပထမ Content ကို ဖန်တီးပါ!',
    en: 'No content created yet. Generate your first content above!',
  },
  'Output Language': {
    my: 'ထွက်လာမည့် ဘာသာစကား',
    en: 'Output Language',
  },
  'Word Count': {
    my: 'စာလုံးအရေအတွက်',
    en: 'Word Count',
  },
  Short: {
    my: 'အတို',
    en: 'Short',
  },
  Medium: {
    my: 'အလယ်အလတ်',
    en: 'Medium',
  },
  Long: {
    my: 'အရှည်',
    en: 'Long',
  },
  'Generated Content:': {
    my: 'ဖန်တီးထားသော Content:',
    en: 'Generated Content:',
  },
  'View My Contents': {
    my: 'ကျွန်ုပ်၏ Content များကြည့်ရန်',
    en: 'View My Contents',
  },
  'View All': {
    my: 'အားလုံးကြည့်ရန်',
    en: 'View All',
  },

  // Contents Dashboard
  'Contents Dashboard': {
    my: 'Content စာမျက်နှာများ',
    en: 'Contents Dashboard',
  },
  'Content Management': {
    my: 'Content စီမံခန့်ခွဲခြင်း',
    en: 'Content Management',
  },
  'Total Contents': {
    my: 'အကြောင်းအရာစုစုပေါင်း',
    en: 'Total Contents',
  },
  Published: {
    my: 'တင်ပြီးသော',
    en: 'Published',
  },
  Drafts: {
    my: 'မတင်ရသေးသော',
    en: 'Drafts',
  },
  Posted: {
    my: 'တင်ပြီး',
    en: 'Published',
  },
  'Not Posted': {
    my: 'မတင်ရသေး',
    en: 'Draft',
  },
  'Search contents...': {
    my: 'Content များကို ရှာဖွေပါ...',
    en: 'Search contents...',
  },
  'All Contents': {
    my: 'Content အားလုံး',
    en: 'All Contents',
  },
  Showing: {
    my: 'ပြသနေသည်',
    en: 'Showing',
  },
  of: {
    my: 'မှ',
    en: 'of',
  },
  'Manage your content library': {
    my: 'သင်၏ Content များကို စီမံခန့်ခွဲပါ',
    en: 'Manage your content library',
  },
  'No contents found': {
    my: 'အကြောင်းအရာရှာမတွေ့ပါ',
    en: 'No contents found',
  },
  'No contents match your search': {
    my: 'သင်ရှာသော အကြောင်းအရာနှင့် ကိုက်ညီမှုမရှိပါ',
    en: 'No contents match your search',
  },
  'Are you sure you want to delete this content?': {
    my: 'ဤ Content ကို ဖျက်လိုသည်မှာ သေချာပါသလား?',
    en: 'Are you sure you want to delete this content?',
  },
  'Delete Content': {
    my: 'Content ဖျက်ရန်',
    en: 'Delete Content',
  },
};

// Get current language from localStorage or default to Myanmar
let currentLanguage = localStorage.getItem('language') || 'my';

// Optimized cache refresh for language data (version 2.6)
const LANGUAGE_VERSION = '2.6';
const storedVersion = localStorage.getItem('language-version');
if (storedVersion !== LANGUAGE_VERSION) {
  // Batch localStorage operations for better performance
  try {
    localStorage.removeItem('language');
    localStorage.setItem('language-version', LANGUAGE_VERSION);
    currentLanguage = 'my'; // Reset to default
  } catch (e) {
    // Fallback if localStorage is not available
    console.warn('localStorage not available, using default language');
    currentLanguage = 'my';
  }
}

// Function to get translation (defined early for immediate use)
function getTranslation(key, lang = currentLanguage) {
  if (translations[key] && translations[key][lang]) {
    return translations[key][lang];
  } else {
    // If no translation found, return the key
    return key;
  }
}

// Export immediately for use in other scripts
window.getTranslation = getTranslation;
window.currentLanguage = currentLanguage;

// Initialize language switcher
document.addEventListener('DOMContentLoaded', function () {
  const languageSelector = document.getElementById('language-selector');

  // Always apply language on page load from localStorage
  applyLanguage(currentLanguage);

  // Update window.currentLanguage for other scripts
  window.currentLanguage = currentLanguage;

  if (languageSelector) {
    // Set initial language
    languageSelector.value = currentLanguage;

    // Add change event listener
    languageSelector.addEventListener('change', function () {
      const selectedLanguage = this.value;
      currentLanguage = selectedLanguage;
      window.currentLanguage = selectedLanguage; // Update global
      localStorage.setItem('language', selectedLanguage);
      applyLanguage(selectedLanguage);
    });
  }
});

// Apply language to all translatable elements
function applyLanguage(language) {
  // Update all elements with data-translate attribute
  const translatableElements = document.querySelectorAll('[data-translate]');

  translatableElements.forEach(element => {
    const key = element.getAttribute('data-translate');
    if (translations[key] && translations[key][language]) {
      if (element.tagName === 'INPUT' && element.type === 'submit') {
        element.value = translations[key][language];
      } else if (element.tagName === 'INPUT' && element.hasAttribute('placeholder')) {
        element.placeholder = translations[key][language];
      } else if (element.tagName === 'OPTION') {
        // Handle option elements
        element.textContent = translations[key][language];
      } else {
        element.textContent = translations[key][language];
      }
    }
  });

  // Update placeholders
  const placeholderElements = document.querySelectorAll('[data-placeholder]');
  placeholderElements.forEach(element => {
    const key = element.getAttribute('data-placeholder');
    if (translations[key] && translations[key][language]) {
      element.placeholder = translations[key][language];
    }
  });

  // Update translate-placeholder elements
  const translatePlaceholderElements = document.querySelectorAll('[data-translate-placeholder]');
  translatePlaceholderElements.forEach(element => {
    const key = element.getAttribute('data-translate-placeholder');
    if (translations[key] && translations[key][language]) {
      element.placeholder = translations[key][language];
    } else {
      // If no translation found, use the key as placeholder
      element.placeholder = key;
    }
  });

  // Update document language attribute
  document.documentElement.lang = language === 'my' ? 'my' : 'en';

  // Update voice generator button
  const voiceGenerateBtn = document.getElementById('generate-voice-content-btn');
  const voiceGenerateBtnText = document.getElementById('generate-voice-btn-text');

  if (voiceGenerateBtn && voiceGenerateBtnText) {
    // Check if button is currently disabled (generating)
    const isGenerating = voiceGenerateBtn.disabled;

    if (isGenerating) {
      // Update to "Generating..." in the selected language
      const generatingText =
        translations['Generating...'] && translations['Generating...'][language]
          ? translations['Generating...'][language]
          : 'Generating...';
      voiceGenerateBtnText.textContent = generatingText;
    } else {
      // Update to "Generate Content" in the selected language
      const generateText =
        translations['Generate Content'] && translations['Generate Content'][language]
          ? translations['Generate Content'][language]
          : 'Generate Content';
      voiceGenerateBtnText.textContent = generateText;
    }
  }

  // Dispatch custom event for countdown timer and other components
  window.dispatchEvent(
    new CustomEvent('languageChanged', {
      detail: { language: language },
    })
  );

  // Update custom select dropdowns
  updateCustomSelects(language);
}

// Function to update custom select dropdowns
function updateCustomSelects(language) {
  // Update all custom select instances
  if (typeof customSelectInstances !== 'undefined' && customSelectInstances.length > 0) {
    customSelectInstances.forEach(instance => {
      // Use the instance's updateTranslations method if available
      if (typeof instance.updateTranslations === 'function') {
        instance.updateTranslations(language);
      } else {
        // Fallback to direct update
        const selectedOption = instance.options[instance.selectedIndex];
        const translateKey = selectedOption.getAttribute('data-translate');
        if (translateKey && translations[translateKey] && translations[translateKey][language]) {
          instance.selectedValue.textContent = translations[translateKey][language];
        }

        // Update all dropdown options
        instance.dropdown.querySelectorAll('.custom-select-option').forEach(optionElement => {
          const key = optionElement.getAttribute('data-translate');
          if (key && translations[key] && translations[key][language]) {
            optionElement.textContent = translations[key][language];
          }
        });
      }
    });
  }
}

// Export applyLanguage and translations for use in other scripts
window.applyLanguage = applyLanguage;
window.translations = translations;

// Helper function to change language and notify all components
window.changeLanguage = function (language) {
  // Update global language variable
  currentLanguage = language;
  window.currentLanguage = language;

  // Save to localStorage
  localStorage.setItem('language', language);

  // Apply language changes
  applyLanguage(language);

  // Dispatch custom event to notify other components (like expiration countdown)
  window.dispatchEvent(
    new CustomEvent('languageChanged', {
      detail: { language: language },
    })
  );
};

// Helper function to get translation
window.getTranslation = function (key, lang) {
  const language = lang || currentLanguage || 'my';
  if (translations[key] && translations[key][language]) {
    return translations[key][language];
  }
  return key; // Return key if translation not found
};
