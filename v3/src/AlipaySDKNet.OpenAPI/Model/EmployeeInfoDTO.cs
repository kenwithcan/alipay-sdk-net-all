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
    /// EmployeeInfoDTO
    /// </summary>
    [DataContract(Name = "EmployeeInfoDTO")]
    public partial class EmployeeInfoDTO : IEquatable<EmployeeInfoDTO>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="EmployeeInfoDTO" /> class.
        /// </summary>
        /// <param name="activate">是否激活.</param>
        /// <param name="departmentList">员工所属部门列表.</param>
        /// <param name="email">员工邮箱.</param>
        /// <param name="employeeCertNo">证件号.</param>
        /// <param name="employeeCertType">证件类型.</param>
        /// <param name="employeeId">员工id.</param>
        /// <param name="employeeName">员工姓名.</param>
        /// <param name="employeeNo">员工编号/工号.</param>
        /// <param name="encryptCertNo">加密证件号（证件号转大写后使用SHA256加密），搭配证件号使用.</param>
        /// <param name="encryptMobile">加密手机号（使用SHA256进行加密）.</param>
        /// <param name="gmtCreate">创建时间.</param>
        /// <param name="gmtModified">变更时间.</param>
        /// <param name="iotFaceStatus">员工是否人脸在库.</param>
        /// <param name="iotUniqueId">IOT开通刷脸支持唯一操作流水号，此处透出用于外部服务商通过该unique_id便捷调用IOT侧接口.</param>
        /// <param name="iotVid">员工在企业人脸库的人脸唯一标识.</param>
        /// <param name="jobLevelShow">员工职级.</param>
        /// <param name="mobile">手机号码.</param>
        /// <param name="openId">用户ID（绑定支付宝账号的uid）.</param>
        /// <param name="profiles">个性化信息 &lt;a href&#x3D;&#39;https://opendocs.alipay.com/pre-open/0ceh47?pathHash&#x3D;14fac87c&#39;&gt;详见文档&lt;/a&gt;.</param>
        /// <param name="roleList">角色列表.</param>
        /// <param name="tlEmployeeId">直属主管员工ID.</param>
        /// <param name="userId">用户ID（绑定支付宝账号的uid）.</param>
        public EmployeeInfoDTO(string activate = default(string), List<EmployeeDepartmentDTO> departmentList = default(List<EmployeeDepartmentDTO>), string email = default(string), string employeeCertNo = default(string), string employeeCertType = default(string), string employeeId = default(string), string employeeName = default(string), string employeeNo = default(string), string encryptCertNo = default(string), string encryptMobile = default(string), string gmtCreate = default(string), string gmtModified = default(string), string iotFaceStatus = default(string), string iotUniqueId = default(string), string iotVid = default(string), string jobLevelShow = default(string), string mobile = default(string), string openId = default(string), string profiles = default(string), List<string> roleList = default(List<string>), string tlEmployeeId = default(string), string userId = default(string))
        {
            this.Activate = activate;
            this.DepartmentList = departmentList;
            this.Email = email;
            this.EmployeeCertNo = employeeCertNo;
            this.EmployeeCertType = employeeCertType;
            this.EmployeeId = employeeId;
            this.EmployeeName = employeeName;
            this.EmployeeNo = employeeNo;
            this.EncryptCertNo = encryptCertNo;
            this.EncryptMobile = encryptMobile;
            this.GmtCreate = gmtCreate;
            this.GmtModified = gmtModified;
            this.IotFaceStatus = iotFaceStatus;
            this.IotUniqueId = iotUniqueId;
            this.IotVid = iotVid;
            this.JobLevelShow = jobLevelShow;
            this.Mobile = mobile;
            this.OpenId = openId;
            this.Profiles = profiles;
            this.RoleList = roleList;
            this.TlEmployeeId = tlEmployeeId;
            this.UserId = userId;
        }

        /// <summary>
        /// 是否激活
        /// </summary>
        /// <value>是否激活</value>
        [DataMember(Name = "activate", EmitDefaultValue = false)]
        public string Activate { get; set; }

        /// <summary>
        /// 员工所属部门列表
        /// </summary>
        /// <value>员工所属部门列表</value>
        [DataMember(Name = "department_list", EmitDefaultValue = false)]
        public List<EmployeeDepartmentDTO> DepartmentList { get; set; }

        /// <summary>
        /// 员工邮箱
        /// </summary>
        /// <value>员工邮箱</value>
        [DataMember(Name = "email", EmitDefaultValue = false)]
        public string Email { get; set; }

        /// <summary>
        /// 证件号
        /// </summary>
        /// <value>证件号</value>
        [DataMember(Name = "employee_cert_no", EmitDefaultValue = false)]
        public string EmployeeCertNo { get; set; }

        /// <summary>
        /// 证件类型
        /// </summary>
        /// <value>证件类型</value>
        [DataMember(Name = "employee_cert_type", EmitDefaultValue = false)]
        public string EmployeeCertType { get; set; }

        /// <summary>
        /// 员工id
        /// </summary>
        /// <value>员工id</value>
        [DataMember(Name = "employee_id", EmitDefaultValue = false)]
        public string EmployeeId { get; set; }

        /// <summary>
        /// 员工姓名
        /// </summary>
        /// <value>员工姓名</value>
        [DataMember(Name = "employee_name", EmitDefaultValue = false)]
        public string EmployeeName { get; set; }

        /// <summary>
        /// 员工编号/工号
        /// </summary>
        /// <value>员工编号/工号</value>
        [DataMember(Name = "employee_no", EmitDefaultValue = false)]
        public string EmployeeNo { get; set; }

        /// <summary>
        /// 加密证件号（证件号转大写后使用SHA256加密），搭配证件号使用
        /// </summary>
        /// <value>加密证件号（证件号转大写后使用SHA256加密），搭配证件号使用</value>
        [DataMember(Name = "encrypt_cert_no", EmitDefaultValue = false)]
        public string EncryptCertNo { get; set; }

        /// <summary>
        /// 加密手机号（使用SHA256进行加密）
        /// </summary>
        /// <value>加密手机号（使用SHA256进行加密）</value>
        [DataMember(Name = "encrypt_mobile", EmitDefaultValue = false)]
        public string EncryptMobile { get; set; }

        /// <summary>
        /// 创建时间
        /// </summary>
        /// <value>创建时间</value>
        [DataMember(Name = "gmt_create", EmitDefaultValue = false)]
        public string GmtCreate { get; set; }

        /// <summary>
        /// 变更时间
        /// </summary>
        /// <value>变更时间</value>
        [DataMember(Name = "gmt_modified", EmitDefaultValue = false)]
        public string GmtModified { get; set; }

        /// <summary>
        /// 员工是否人脸在库
        /// </summary>
        /// <value>员工是否人脸在库</value>
        [DataMember(Name = "iot_face_status", EmitDefaultValue = false)]
        public string IotFaceStatus { get; set; }

        /// <summary>
        /// IOT开通刷脸支持唯一操作流水号，此处透出用于外部服务商通过该unique_id便捷调用IOT侧接口
        /// </summary>
        /// <value>IOT开通刷脸支持唯一操作流水号，此处透出用于外部服务商通过该unique_id便捷调用IOT侧接口</value>
        [DataMember(Name = "iot_unique_id", EmitDefaultValue = false)]
        public string IotUniqueId { get; set; }

        /// <summary>
        /// 员工在企业人脸库的人脸唯一标识
        /// </summary>
        /// <value>员工在企业人脸库的人脸唯一标识</value>
        [DataMember(Name = "iot_vid", EmitDefaultValue = false)]
        public string IotVid { get; set; }

        /// <summary>
        /// 员工职级
        /// </summary>
        /// <value>员工职级</value>
        [DataMember(Name = "job_level_show", EmitDefaultValue = false)]
        public string JobLevelShow { get; set; }

        /// <summary>
        /// 手机号码
        /// </summary>
        /// <value>手机号码</value>
        [DataMember(Name = "mobile", EmitDefaultValue = false)]
        public string Mobile { get; set; }

        /// <summary>
        /// 用户ID（绑定支付宝账号的uid）
        /// </summary>
        /// <value>用户ID（绑定支付宝账号的uid）</value>
        [DataMember(Name = "open_id", EmitDefaultValue = false)]
        public string OpenId { get; set; }

        /// <summary>
        /// 个性化信息 &lt;a href&#x3D;&#39;https://opendocs.alipay.com/pre-open/0ceh47?pathHash&#x3D;14fac87c&#39;&gt;详见文档&lt;/a&gt;
        /// </summary>
        /// <value>个性化信息 &lt;a href&#x3D;&#39;https://opendocs.alipay.com/pre-open/0ceh47?pathHash&#x3D;14fac87c&#39;&gt;详见文档&lt;/a&gt;</value>
        [DataMember(Name = "profiles", EmitDefaultValue = false)]
        public string Profiles { get; set; }

        /// <summary>
        /// 角色列表
        /// </summary>
        /// <value>角色列表</value>
        [DataMember(Name = "role_list", EmitDefaultValue = false)]
        public List<string> RoleList { get; set; }

        /// <summary>
        /// 直属主管员工ID
        /// </summary>
        /// <value>直属主管员工ID</value>
        [DataMember(Name = "tl_employee_id", EmitDefaultValue = false)]
        public string TlEmployeeId { get; set; }

        /// <summary>
        /// 用户ID（绑定支付宝账号的uid）
        /// </summary>
        /// <value>用户ID（绑定支付宝账号的uid）</value>
        [DataMember(Name = "user_id", EmitDefaultValue = false)]
        public string UserId { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class EmployeeInfoDTO {\n");
            sb.Append("  Activate: ").Append(Activate).Append("\n");
            sb.Append("  DepartmentList: ").Append(DepartmentList).Append("\n");
            sb.Append("  Email: ").Append(Email).Append("\n");
            sb.Append("  EmployeeCertNo: ").Append(EmployeeCertNo).Append("\n");
            sb.Append("  EmployeeCertType: ").Append(EmployeeCertType).Append("\n");
            sb.Append("  EmployeeId: ").Append(EmployeeId).Append("\n");
            sb.Append("  EmployeeName: ").Append(EmployeeName).Append("\n");
            sb.Append("  EmployeeNo: ").Append(EmployeeNo).Append("\n");
            sb.Append("  EncryptCertNo: ").Append(EncryptCertNo).Append("\n");
            sb.Append("  EncryptMobile: ").Append(EncryptMobile).Append("\n");
            sb.Append("  GmtCreate: ").Append(GmtCreate).Append("\n");
            sb.Append("  GmtModified: ").Append(GmtModified).Append("\n");
            sb.Append("  IotFaceStatus: ").Append(IotFaceStatus).Append("\n");
            sb.Append("  IotUniqueId: ").Append(IotUniqueId).Append("\n");
            sb.Append("  IotVid: ").Append(IotVid).Append("\n");
            sb.Append("  JobLevelShow: ").Append(JobLevelShow).Append("\n");
            sb.Append("  Mobile: ").Append(Mobile).Append("\n");
            sb.Append("  OpenId: ").Append(OpenId).Append("\n");
            sb.Append("  Profiles: ").Append(Profiles).Append("\n");
            sb.Append("  RoleList: ").Append(RoleList).Append("\n");
            sb.Append("  TlEmployeeId: ").Append(TlEmployeeId).Append("\n");
            sb.Append("  UserId: ").Append(UserId).Append("\n");
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
            return this.Equals(input as EmployeeInfoDTO);
        }

        /// <summary>
        /// Returns true if EmployeeInfoDTO instances are equal
        /// </summary>
        /// <param name="input">Instance of EmployeeInfoDTO to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(EmployeeInfoDTO input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.Activate == input.Activate ||
                    (this.Activate != null &&
                    this.Activate.Equals(input.Activate))
                ) && 
                (
                    this.DepartmentList == input.DepartmentList ||
                    this.DepartmentList != null &&
                    input.DepartmentList != null &&
                    this.DepartmentList.SequenceEqual(input.DepartmentList)
                ) && 
                (
                    this.Email == input.Email ||
                    (this.Email != null &&
                    this.Email.Equals(input.Email))
                ) && 
                (
                    this.EmployeeCertNo == input.EmployeeCertNo ||
                    (this.EmployeeCertNo != null &&
                    this.EmployeeCertNo.Equals(input.EmployeeCertNo))
                ) && 
                (
                    this.EmployeeCertType == input.EmployeeCertType ||
                    (this.EmployeeCertType != null &&
                    this.EmployeeCertType.Equals(input.EmployeeCertType))
                ) && 
                (
                    this.EmployeeId == input.EmployeeId ||
                    (this.EmployeeId != null &&
                    this.EmployeeId.Equals(input.EmployeeId))
                ) && 
                (
                    this.EmployeeName == input.EmployeeName ||
                    (this.EmployeeName != null &&
                    this.EmployeeName.Equals(input.EmployeeName))
                ) && 
                (
                    this.EmployeeNo == input.EmployeeNo ||
                    (this.EmployeeNo != null &&
                    this.EmployeeNo.Equals(input.EmployeeNo))
                ) && 
                (
                    this.EncryptCertNo == input.EncryptCertNo ||
                    (this.EncryptCertNo != null &&
                    this.EncryptCertNo.Equals(input.EncryptCertNo))
                ) && 
                (
                    this.EncryptMobile == input.EncryptMobile ||
                    (this.EncryptMobile != null &&
                    this.EncryptMobile.Equals(input.EncryptMobile))
                ) && 
                (
                    this.GmtCreate == input.GmtCreate ||
                    (this.GmtCreate != null &&
                    this.GmtCreate.Equals(input.GmtCreate))
                ) && 
                (
                    this.GmtModified == input.GmtModified ||
                    (this.GmtModified != null &&
                    this.GmtModified.Equals(input.GmtModified))
                ) && 
                (
                    this.IotFaceStatus == input.IotFaceStatus ||
                    (this.IotFaceStatus != null &&
                    this.IotFaceStatus.Equals(input.IotFaceStatus))
                ) && 
                (
                    this.IotUniqueId == input.IotUniqueId ||
                    (this.IotUniqueId != null &&
                    this.IotUniqueId.Equals(input.IotUniqueId))
                ) && 
                (
                    this.IotVid == input.IotVid ||
                    (this.IotVid != null &&
                    this.IotVid.Equals(input.IotVid))
                ) && 
                (
                    this.JobLevelShow == input.JobLevelShow ||
                    (this.JobLevelShow != null &&
                    this.JobLevelShow.Equals(input.JobLevelShow))
                ) && 
                (
                    this.Mobile == input.Mobile ||
                    (this.Mobile != null &&
                    this.Mobile.Equals(input.Mobile))
                ) && 
                (
                    this.OpenId == input.OpenId ||
                    (this.OpenId != null &&
                    this.OpenId.Equals(input.OpenId))
                ) && 
                (
                    this.Profiles == input.Profiles ||
                    (this.Profiles != null &&
                    this.Profiles.Equals(input.Profiles))
                ) && 
                (
                    this.RoleList == input.RoleList ||
                    this.RoleList != null &&
                    input.RoleList != null &&
                    this.RoleList.SequenceEqual(input.RoleList)
                ) && 
                (
                    this.TlEmployeeId == input.TlEmployeeId ||
                    (this.TlEmployeeId != null &&
                    this.TlEmployeeId.Equals(input.TlEmployeeId))
                ) && 
                (
                    this.UserId == input.UserId ||
                    (this.UserId != null &&
                    this.UserId.Equals(input.UserId))
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
                if (this.Activate != null)
                {
                    hashCode = (hashCode * 59) + this.Activate.GetHashCode();
                }
                if (this.DepartmentList != null)
                {
                    hashCode = (hashCode * 59) + this.DepartmentList.GetHashCode();
                }
                if (this.Email != null)
                {
                    hashCode = (hashCode * 59) + this.Email.GetHashCode();
                }
                if (this.EmployeeCertNo != null)
                {
                    hashCode = (hashCode * 59) + this.EmployeeCertNo.GetHashCode();
                }
                if (this.EmployeeCertType != null)
                {
                    hashCode = (hashCode * 59) + this.EmployeeCertType.GetHashCode();
                }
                if (this.EmployeeId != null)
                {
                    hashCode = (hashCode * 59) + this.EmployeeId.GetHashCode();
                }
                if (this.EmployeeName != null)
                {
                    hashCode = (hashCode * 59) + this.EmployeeName.GetHashCode();
                }
                if (this.EmployeeNo != null)
                {
                    hashCode = (hashCode * 59) + this.EmployeeNo.GetHashCode();
                }
                if (this.EncryptCertNo != null)
                {
                    hashCode = (hashCode * 59) + this.EncryptCertNo.GetHashCode();
                }
                if (this.EncryptMobile != null)
                {
                    hashCode = (hashCode * 59) + this.EncryptMobile.GetHashCode();
                }
                if (this.GmtCreate != null)
                {
                    hashCode = (hashCode * 59) + this.GmtCreate.GetHashCode();
                }
                if (this.GmtModified != null)
                {
                    hashCode = (hashCode * 59) + this.GmtModified.GetHashCode();
                }
                if (this.IotFaceStatus != null)
                {
                    hashCode = (hashCode * 59) + this.IotFaceStatus.GetHashCode();
                }
                if (this.IotUniqueId != null)
                {
                    hashCode = (hashCode * 59) + this.IotUniqueId.GetHashCode();
                }
                if (this.IotVid != null)
                {
                    hashCode = (hashCode * 59) + this.IotVid.GetHashCode();
                }
                if (this.JobLevelShow != null)
                {
                    hashCode = (hashCode * 59) + this.JobLevelShow.GetHashCode();
                }
                if (this.Mobile != null)
                {
                    hashCode = (hashCode * 59) + this.Mobile.GetHashCode();
                }
                if (this.OpenId != null)
                {
                    hashCode = (hashCode * 59) + this.OpenId.GetHashCode();
                }
                if (this.Profiles != null)
                {
                    hashCode = (hashCode * 59) + this.Profiles.GetHashCode();
                }
                if (this.RoleList != null)
                {
                    hashCode = (hashCode * 59) + this.RoleList.GetHashCode();
                }
                if (this.TlEmployeeId != null)
                {
                    hashCode = (hashCode * 59) + this.TlEmployeeId.GetHashCode();
                }
                if (this.UserId != null)
                {
                    hashCode = (hashCode * 59) + this.UserId.GetHashCode();
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
