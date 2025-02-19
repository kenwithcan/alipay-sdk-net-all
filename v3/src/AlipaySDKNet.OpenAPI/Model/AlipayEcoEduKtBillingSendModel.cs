/*
 * 支付宝开放平台API
 *
 * 支付宝开放平台v3协议文档
 *
 * The version of the OpenAPI document: 2025-02-19
 * Generated by: https://github.com/openapitools/openapi-generator.git
 */


using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.IO;
using System.Runtime.Serialization;
using System.Text;
using System.Text.RegularExpressions;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Newtonsoft.Json.Linq;
using System.ComponentModel.DataAnnotations;
using OpenAPIDateConverter = AlipaySDKNet.OpenAPI.Client.OpenAPIDateConverter;

namespace AlipaySDKNet.OpenAPI.Model
{
    /// <summary>
    /// AlipayEcoEduKtBillingSendModel
    /// </summary>
    [DataContract(Name = "AlipayEcoEduKtBillingSendModel")]
    public partial class AlipayEcoEduKtBillingSendModel : IEquatable<AlipayEcoEduKtBillingSendModel>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayEcoEduKtBillingSendModel" /> class.
        /// </summary>
        /// <param name="amount">总金额，单位为元，精确到小数点后两位，取值范围[0.01,100000000]，  如果是非多选项，是要和缴费项的总和相同，多选模式不做验证.</param>
        /// <param name="chargeBillTitle">缴费账单名称.</param>
        /// <param name="chargeItem">缴费详情：输入json格式字符串。Json定义：key填写缴费项名称，value填写缴费项金额，金额保留2位小数（单位：元）.</param>
        /// <param name="chargeType">缴费项模式：空或\&quot;N\&quot;，表示缴费项不可选，  \&quot;M\&quot;表示缴费项为可选 ，支持单选和多选。.</param>
        /// <param name="childName">孩子名字.</param>
        /// <param name="classIn">孩子所在班级.</param>
        /// <param name="endEnable">截止日期是否生效，与gmt_end发布配合使用,N为gmt_end不生效，用户过期后仍可以缴费；Y为gmt_end生效，用户过期后，不能再缴费。.</param>
        /// <param name="extInfo">extInfo.</param>
        /// <param name="gmtEnd">缴费截止时间，格式\&quot;yyyy-MM-dd HH:mm:ss\&quot;，日期要大于当前时间。请注意，过期时间不宜设置过短。.</param>
        /// <param name="grade">孩子所在年级.</param>
        /// <param name="outTradeNo">ISV端的缴费账单编号.</param>
        /// <param name="partnerId">Isv支付宝pid, 支付宝签约后，返回给ISV编号.</param>
        /// <param name="schoolNo">学校编码，录入学校接口返回的参数.</param>
        /// <param name="schoolPid">学校支付宝pid,直付通填写smid.</param>
        /// <param name="studentCode">学生的学号，只支持字母和数字类型，一般以教育局学号为准，作为学生的唯一标识。此字段与student_identify、家长user_mobile至少选一个.</param>
        /// <param name="studentIdentify">学生的身份证号，如果ISV有学生身份证号，则同步身份证号作为学生唯一标识。此字段与student_code、家长user_mobile至少选一个。  大陆身份证必须是18位 ， 其它地区或国家的身份证开头需要加\&quot;IC\&quot;开头区分并且不超过18位，但查询账单的时候不要带\&quot;IC\&quot;.</param>
        /// <param name="users">孩子的家长信息，最多一次输入10个家长，此字段做为识别家长的孩子用，与student_identify、student_code至少选一个.</param>
        public AlipayEcoEduKtBillingSendModel(string amount = default(string), string chargeBillTitle = default(string), List<ChargeItems> chargeItem = default(List<ChargeItems>), string chargeType = default(string), string childName = default(string), string classIn = default(string), string endEnable = default(string), BillSendExtInfo extInfo = default(BillSendExtInfo), string gmtEnd = default(string), string grade = default(string), string outTradeNo = default(string), string partnerId = default(string), string schoolNo = default(string), string schoolPid = default(string), string studentCode = default(string), string studentIdentify = default(string), List<UserDetails> users = default(List<UserDetails>))
        {
            this.Amount = amount;
            this.ChargeBillTitle = chargeBillTitle;
            this.ChargeItem = chargeItem;
            this.ChargeType = chargeType;
            this.ChildName = childName;
            this.ClassIn = classIn;
            this.EndEnable = endEnable;
            this.ExtInfo = extInfo;
            this.GmtEnd = gmtEnd;
            this.Grade = grade;
            this.OutTradeNo = outTradeNo;
            this.PartnerId = partnerId;
            this.SchoolNo = schoolNo;
            this.SchoolPid = schoolPid;
            this.StudentCode = studentCode;
            this.StudentIdentify = studentIdentify;
            this.Users = users;
        }

        /// <summary>
        /// 总金额，单位为元，精确到小数点后两位，取值范围[0.01,100000000]，  如果是非多选项，是要和缴费项的总和相同，多选模式不做验证
        /// </summary>
        /// <value>总金额，单位为元，精确到小数点后两位，取值范围[0.01,100000000]，  如果是非多选项，是要和缴费项的总和相同，多选模式不做验证</value>
        [DataMember(Name = "amount", EmitDefaultValue = false)]
        public string Amount { get; set; }

        /// <summary>
        /// 缴费账单名称
        /// </summary>
        /// <value>缴费账单名称</value>
        [DataMember(Name = "charge_bill_title", EmitDefaultValue = false)]
        public string ChargeBillTitle { get; set; }

        /// <summary>
        /// 缴费详情：输入json格式字符串。Json定义：key填写缴费项名称，value填写缴费项金额，金额保留2位小数（单位：元）
        /// </summary>
        /// <value>缴费详情：输入json格式字符串。Json定义：key填写缴费项名称，value填写缴费项金额，金额保留2位小数（单位：元）</value>
        [DataMember(Name = "charge_item", EmitDefaultValue = false)]
        public List<ChargeItems> ChargeItem { get; set; }

        /// <summary>
        /// 缴费项模式：空或\&quot;N\&quot;，表示缴费项不可选，  \&quot;M\&quot;表示缴费项为可选 ，支持单选和多选。
        /// </summary>
        /// <value>缴费项模式：空或\&quot;N\&quot;，表示缴费项不可选，  \&quot;M\&quot;表示缴费项为可选 ，支持单选和多选。</value>
        [DataMember(Name = "charge_type", EmitDefaultValue = false)]
        public string ChargeType { get; set; }

        /// <summary>
        /// 孩子名字
        /// </summary>
        /// <value>孩子名字</value>
        [DataMember(Name = "child_name", EmitDefaultValue = false)]
        public string ChildName { get; set; }

        /// <summary>
        /// 孩子所在班级
        /// </summary>
        /// <value>孩子所在班级</value>
        [DataMember(Name = "class_in", EmitDefaultValue = false)]
        public string ClassIn { get; set; }

        /// <summary>
        /// 截止日期是否生效，与gmt_end发布配合使用,N为gmt_end不生效，用户过期后仍可以缴费；Y为gmt_end生效，用户过期后，不能再缴费。
        /// </summary>
        /// <value>截止日期是否生效，与gmt_end发布配合使用,N为gmt_end不生效，用户过期后仍可以缴费；Y为gmt_end生效，用户过期后，不能再缴费。</value>
        [DataMember(Name = "end_enable", EmitDefaultValue = false)]
        public string EndEnable { get; set; }

        /// <summary>
        /// Gets or Sets ExtInfo
        /// </summary>
        [DataMember(Name = "ext_info", EmitDefaultValue = false)]
        public BillSendExtInfo ExtInfo { get; set; }

        /// <summary>
        /// 缴费截止时间，格式\&quot;yyyy-MM-dd HH:mm:ss\&quot;，日期要大于当前时间。请注意，过期时间不宜设置过短。
        /// </summary>
        /// <value>缴费截止时间，格式\&quot;yyyy-MM-dd HH:mm:ss\&quot;，日期要大于当前时间。请注意，过期时间不宜设置过短。</value>
        [DataMember(Name = "gmt_end", EmitDefaultValue = false)]
        public string GmtEnd { get; set; }

        /// <summary>
        /// 孩子所在年级
        /// </summary>
        /// <value>孩子所在年级</value>
        [DataMember(Name = "grade", EmitDefaultValue = false)]
        public string Grade { get; set; }

        /// <summary>
        /// ISV端的缴费账单编号
        /// </summary>
        /// <value>ISV端的缴费账单编号</value>
        [DataMember(Name = "out_trade_no", EmitDefaultValue = false)]
        public string OutTradeNo { get; set; }

        /// <summary>
        /// Isv支付宝pid, 支付宝签约后，返回给ISV编号
        /// </summary>
        /// <value>Isv支付宝pid, 支付宝签约后，返回给ISV编号</value>
        [DataMember(Name = "partner_id", EmitDefaultValue = false)]
        public string PartnerId { get; set; }

        /// <summary>
        /// 学校编码，录入学校接口返回的参数
        /// </summary>
        /// <value>学校编码，录入学校接口返回的参数</value>
        [DataMember(Name = "school_no", EmitDefaultValue = false)]
        public string SchoolNo { get; set; }

        /// <summary>
        /// 学校支付宝pid,直付通填写smid
        /// </summary>
        /// <value>学校支付宝pid,直付通填写smid</value>
        [DataMember(Name = "school_pid", EmitDefaultValue = false)]
        public string SchoolPid { get; set; }

        /// <summary>
        /// 学生的学号，只支持字母和数字类型，一般以教育局学号为准，作为学生的唯一标识。此字段与student_identify、家长user_mobile至少选一个
        /// </summary>
        /// <value>学生的学号，只支持字母和数字类型，一般以教育局学号为准，作为学生的唯一标识。此字段与student_identify、家长user_mobile至少选一个</value>
        [DataMember(Name = "student_code", EmitDefaultValue = false)]
        public string StudentCode { get; set; }

        /// <summary>
        /// 学生的身份证号，如果ISV有学生身份证号，则同步身份证号作为学生唯一标识。此字段与student_code、家长user_mobile至少选一个。  大陆身份证必须是18位 ， 其它地区或国家的身份证开头需要加\&quot;IC\&quot;开头区分并且不超过18位，但查询账单的时候不要带\&quot;IC\&quot;
        /// </summary>
        /// <value>学生的身份证号，如果ISV有学生身份证号，则同步身份证号作为学生唯一标识。此字段与student_code、家长user_mobile至少选一个。  大陆身份证必须是18位 ， 其它地区或国家的身份证开头需要加\&quot;IC\&quot;开头区分并且不超过18位，但查询账单的时候不要带\&quot;IC\&quot;</value>
        [DataMember(Name = "student_identify", EmitDefaultValue = false)]
        public string StudentIdentify { get; set; }

        /// <summary>
        /// 孩子的家长信息，最多一次输入10个家长，此字段做为识别家长的孩子用，与student_identify、student_code至少选一个
        /// </summary>
        /// <value>孩子的家长信息，最多一次输入10个家长，此字段做为识别家长的孩子用，与student_identify、student_code至少选一个</value>
        [DataMember(Name = "users", EmitDefaultValue = false)]
        public List<UserDetails> Users { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class AlipayEcoEduKtBillingSendModel {\n");
            sb.Append("  Amount: ").Append(Amount).Append("\n");
            sb.Append("  ChargeBillTitle: ").Append(ChargeBillTitle).Append("\n");
            sb.Append("  ChargeItem: ").Append(ChargeItem).Append("\n");
            sb.Append("  ChargeType: ").Append(ChargeType).Append("\n");
            sb.Append("  ChildName: ").Append(ChildName).Append("\n");
            sb.Append("  ClassIn: ").Append(ClassIn).Append("\n");
            sb.Append("  EndEnable: ").Append(EndEnable).Append("\n");
            sb.Append("  ExtInfo: ").Append(ExtInfo).Append("\n");
            sb.Append("  GmtEnd: ").Append(GmtEnd).Append("\n");
            sb.Append("  Grade: ").Append(Grade).Append("\n");
            sb.Append("  OutTradeNo: ").Append(OutTradeNo).Append("\n");
            sb.Append("  PartnerId: ").Append(PartnerId).Append("\n");
            sb.Append("  SchoolNo: ").Append(SchoolNo).Append("\n");
            sb.Append("  SchoolPid: ").Append(SchoolPid).Append("\n");
            sb.Append("  StudentCode: ").Append(StudentCode).Append("\n");
            sb.Append("  StudentIdentify: ").Append(StudentIdentify).Append("\n");
            sb.Append("  Users: ").Append(Users).Append("\n");
            sb.Append("}\n");
            return sb.ToString();
        }

        /// <summary>
        /// Returns the JSON string presentation of the object
        /// </summary>
        /// <returns>JSON string presentation of the object</returns>
        public virtual string ToJson()
        {
            return Newtonsoft.Json.JsonConvert.SerializeObject(this, Newtonsoft.Json.Formatting.Indented);
        }

        /// <summary>
        /// Returns true if objects are equal
        /// </summary>
        /// <param name="input">Object to be compared</param>
        /// <returns>Boolean</returns>
        public override bool Equals(object input)
        {
            return this.Equals(input as AlipayEcoEduKtBillingSendModel);
        }

        /// <summary>
        /// Returns true if AlipayEcoEduKtBillingSendModel instances are equal
        /// </summary>
        /// <param name="input">Instance of AlipayEcoEduKtBillingSendModel to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(AlipayEcoEduKtBillingSendModel input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.Amount == input.Amount ||
                    (this.Amount != null &&
                    this.Amount.Equals(input.Amount))
                ) && 
                (
                    this.ChargeBillTitle == input.ChargeBillTitle ||
                    (this.ChargeBillTitle != null &&
                    this.ChargeBillTitle.Equals(input.ChargeBillTitle))
                ) && 
                (
                    this.ChargeItem == input.ChargeItem ||
                    this.ChargeItem != null &&
                    input.ChargeItem != null &&
                    this.ChargeItem.SequenceEqual(input.ChargeItem)
                ) && 
                (
                    this.ChargeType == input.ChargeType ||
                    (this.ChargeType != null &&
                    this.ChargeType.Equals(input.ChargeType))
                ) && 
                (
                    this.ChildName == input.ChildName ||
                    (this.ChildName != null &&
                    this.ChildName.Equals(input.ChildName))
                ) && 
                (
                    this.ClassIn == input.ClassIn ||
                    (this.ClassIn != null &&
                    this.ClassIn.Equals(input.ClassIn))
                ) && 
                (
                    this.EndEnable == input.EndEnable ||
                    (this.EndEnable != null &&
                    this.EndEnable.Equals(input.EndEnable))
                ) && 
                (
                    this.ExtInfo == input.ExtInfo ||
                    (this.ExtInfo != null &&
                    this.ExtInfo.Equals(input.ExtInfo))
                ) && 
                (
                    this.GmtEnd == input.GmtEnd ||
                    (this.GmtEnd != null &&
                    this.GmtEnd.Equals(input.GmtEnd))
                ) && 
                (
                    this.Grade == input.Grade ||
                    (this.Grade != null &&
                    this.Grade.Equals(input.Grade))
                ) && 
                (
                    this.OutTradeNo == input.OutTradeNo ||
                    (this.OutTradeNo != null &&
                    this.OutTradeNo.Equals(input.OutTradeNo))
                ) && 
                (
                    this.PartnerId == input.PartnerId ||
                    (this.PartnerId != null &&
                    this.PartnerId.Equals(input.PartnerId))
                ) && 
                (
                    this.SchoolNo == input.SchoolNo ||
                    (this.SchoolNo != null &&
                    this.SchoolNo.Equals(input.SchoolNo))
                ) && 
                (
                    this.SchoolPid == input.SchoolPid ||
                    (this.SchoolPid != null &&
                    this.SchoolPid.Equals(input.SchoolPid))
                ) && 
                (
                    this.StudentCode == input.StudentCode ||
                    (this.StudentCode != null &&
                    this.StudentCode.Equals(input.StudentCode))
                ) && 
                (
                    this.StudentIdentify == input.StudentIdentify ||
                    (this.StudentIdentify != null &&
                    this.StudentIdentify.Equals(input.StudentIdentify))
                ) && 
                (
                    this.Users == input.Users ||
                    this.Users != null &&
                    input.Users != null &&
                    this.Users.SequenceEqual(input.Users)
                );
        }

        /// <summary>
        /// Gets the hash code
        /// </summary>
        /// <returns>Hash code</returns>
        public override int GetHashCode()
        {
            unchecked // Overflow is fine, just wrap
            {
                int hashCode = 41;
                if (this.Amount != null)
                {
                    hashCode = (hashCode * 59) + this.Amount.GetHashCode();
                }
                if (this.ChargeBillTitle != null)
                {
                    hashCode = (hashCode * 59) + this.ChargeBillTitle.GetHashCode();
                }
                if (this.ChargeItem != null)
                {
                    hashCode = (hashCode * 59) + this.ChargeItem.GetHashCode();
                }
                if (this.ChargeType != null)
                {
                    hashCode = (hashCode * 59) + this.ChargeType.GetHashCode();
                }
                if (this.ChildName != null)
                {
                    hashCode = (hashCode * 59) + this.ChildName.GetHashCode();
                }
                if (this.ClassIn != null)
                {
                    hashCode = (hashCode * 59) + this.ClassIn.GetHashCode();
                }
                if (this.EndEnable != null)
                {
                    hashCode = (hashCode * 59) + this.EndEnable.GetHashCode();
                }
                if (this.ExtInfo != null)
                {
                    hashCode = (hashCode * 59) + this.ExtInfo.GetHashCode();
                }
                if (this.GmtEnd != null)
                {
                    hashCode = (hashCode * 59) + this.GmtEnd.GetHashCode();
                }
                if (this.Grade != null)
                {
                    hashCode = (hashCode * 59) + this.Grade.GetHashCode();
                }
                if (this.OutTradeNo != null)
                {
                    hashCode = (hashCode * 59) + this.OutTradeNo.GetHashCode();
                }
                if (this.PartnerId != null)
                {
                    hashCode = (hashCode * 59) + this.PartnerId.GetHashCode();
                }
                if (this.SchoolNo != null)
                {
                    hashCode = (hashCode * 59) + this.SchoolNo.GetHashCode();
                }
                if (this.SchoolPid != null)
                {
                    hashCode = (hashCode * 59) + this.SchoolPid.GetHashCode();
                }
                if (this.StudentCode != null)
                {
                    hashCode = (hashCode * 59) + this.StudentCode.GetHashCode();
                }
                if (this.StudentIdentify != null)
                {
                    hashCode = (hashCode * 59) + this.StudentIdentify.GetHashCode();
                }
                if (this.Users != null)
                {
                    hashCode = (hashCode * 59) + this.Users.GetHashCode();
                }
                return hashCode;
            }
        }

        /// <summary>
        /// To validate all properties of the instance
        /// </summary>
        /// <param name="validationContext">Validation context</param>
        /// <returns>Validation Result</returns>
        public IEnumerable<System.ComponentModel.DataAnnotations.ValidationResult> Validate(ValidationContext validationContext)
        {
            yield break;
        }
    }

}
