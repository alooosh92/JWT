# JWT Token
## يجب اجراء التعديلات التالية لانشاء مشروع يتوافق مع تقنية JWT
### يجب اضافة المعلومات الايميل و التوغين في ملف  appsettings.cs
### يجب نسخ الكود المحدد بتاغ ج و ت الموجود في ملف Program.cs 
### نسخ المجلد كاملا مع تغيير الفضاء Data/JWT
### لحماية الكنترول من الدخول غير المصرح نضع  [Authorize(AuthenticationSchemes = "Bearer")]
### كما يمكن اضافة الصلاحيات مثال [Authorize(AuthenticationSchemes = "Bearer",Roles = "User")]
### يجب اضافة جدول refreshToken to applicationDbContex
