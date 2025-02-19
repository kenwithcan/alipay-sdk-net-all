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
    /// ZolozAuthenticationCustomerFacemanageCreateModel
    /// </summary>
    [DataContract(Name = "ZolozAuthenticationCustomerFacemanageCreateModel")]
    public partial class ZolozAuthenticationCustomerFacemanageCreateModel : IEquatable<ZolozAuthenticationCustomerFacemanageCreateModel>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="ZolozAuthenticationCustomerFacemanageCreateModel" /> class.
        /// </summary>
        /// <param name="areacode">地域编码.</param>
        /// <param name="bizType">人脸产品能力，预热场景，需要传college，k12，scenic，subway，traffic。具体值视具体场景.</param>
        /// <param name="bizscale">业务量规模.</param>
        /// <param name="brandcode">商户品牌.</param>
        /// <param name="devicenum">商户机具唯一编码，关键参数 人脸预热，传logicGroupId.</param>
        /// <param name="extinfo">拓展参数.</param>
        /// <param name="facetype">入库类型 IDCARD:身份证 ALIPAY_USER:支付宝用户id, ALIPAY_TEL:手机号入库 CUSTOMER:自定义 DIRECT_CLIENT_PRE：本地预写入 DIRECT_CLIENT：本地客户端库 ENCLOSED：封闭场景.</param>
        /// <param name="faceval">入库用户信息 人脸预热，alipayUid必填.</param>
        /// <param name="group">分组5.</param>
        /// <param name="storecode">门店编码.</param>
        /// <param name="validtimes">有效期天数，如7天、30天、365天.</param>
        public ZolozAuthenticationCustomerFacemanageCreateModel(string areacode = default(string), string bizType = default(string), string bizscale = default(string), string brandcode = default(string), string devicenum = default(string), string extinfo = default(string), string facetype = default(string), string faceval = default(string), string group = default(string), string storecode = default(string), string validtimes = default(string))
        {
            this.Areacode = areacode;
            this.BizType = bizType;
            this.Bizscale = bizscale;
            this.Brandcode = brandcode;
            this.Devicenum = devicenum;
            this.Extinfo = extinfo;
            this.Facetype = facetype;
            this.Faceval = faceval;
            this.Group = group;
            this.Storecode = storecode;
            this.Validtimes = validtimes;
        }

        /// <summary>
        /// 地域编码
        /// </summary>
        /// <value>地域编码</value>
        [DataMember(Name = "areacode", EmitDefaultValue = false)]
        public string Areacode { get; set; }

        /// <summary>
        /// 人脸产品能力，预热场景，需要传college，k12，scenic，subway，traffic。具体值视具体场景
        /// </summary>
        /// <value>人脸产品能力，预热场景，需要传college，k12，scenic，subway，traffic。具体值视具体场景</value>
        [DataMember(Name = "biz_type", EmitDefaultValue = false)]
        public string BizType { get; set; }

        /// <summary>
        /// 业务量规模
        /// </summary>
        /// <value>业务量规模</value>
        [DataMember(Name = "bizscale", EmitDefaultValue = false)]
        public string Bizscale { get; set; }

        /// <summary>
        /// 商户品牌
        /// </summary>
        /// <value>商户品牌</value>
        [DataMember(Name = "brandcode", EmitDefaultValue = false)]
        public string Brandcode { get; set; }

        /// <summary>
        /// 商户机具唯一编码，关键参数 人脸预热，传logicGroupId
        /// </summary>
        /// <value>商户机具唯一编码，关键参数 人脸预热，传logicGroupId</value>
        [DataMember(Name = "devicenum", EmitDefaultValue = false)]
        public string Devicenum { get; set; }

        /// <summary>
        /// 拓展参数
        /// </summary>
        /// <value>拓展参数</value>
        [DataMember(Name = "extinfo", EmitDefaultValue = false)]
        public string Extinfo { get; set; }

        /// <summary>
        /// 入库类型 IDCARD:身份证 ALIPAY_USER:支付宝用户id, ALIPAY_TEL:手机号入库 CUSTOMER:自定义 DIRECT_CLIENT_PRE：本地预写入 DIRECT_CLIENT：本地客户端库 ENCLOSED：封闭场景
        /// </summary>
        /// <value>入库类型 IDCARD:身份证 ALIPAY_USER:支付宝用户id, ALIPAY_TEL:手机号入库 CUSTOMER:自定义 DIRECT_CLIENT_PRE：本地预写入 DIRECT_CLIENT：本地客户端库 ENCLOSED：封闭场景</value>
        [DataMember(Name = "facetype", EmitDefaultValue = false)]
        public string Facetype { get; set; }

        /// <summary>
        /// 入库用户信息 人脸预热，alipayUid必填
        /// </summary>
        /// <value>入库用户信息 人脸预热，alipayUid必填</value>
        [DataMember(Name = "faceval", EmitDefaultValue = false)]
        public string Faceval { get; set; }

        /// <summary>
        /// 分组5
        /// </summary>
        /// <value>分组5</value>
        [DataMember(Name = "group", EmitDefaultValue = false)]
        public string Group { get; set; }

        /// <summary>
        /// 门店编码
        /// </summary>
        /// <value>门店编码</value>
        [DataMember(Name = "storecode", EmitDefaultValue = false)]
        public string Storecode { get; set; }

        /// <summary>
        /// 有效期天数，如7天、30天、365天
        /// </summary>
        /// <value>有效期天数，如7天、30天、365天</value>
        [DataMember(Name = "validtimes", EmitDefaultValue = false)]
        public string Validtimes { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class ZolozAuthenticationCustomerFacemanageCreateModel {\n");
            sb.Append("  Areacode: ").Append(Areacode).Append("\n");
            sb.Append("  BizType: ").Append(BizType).Append("\n");
            sb.Append("  Bizscale: ").Append(Bizscale).Append("\n");
            sb.Append("  Brandcode: ").Append(Brandcode).Append("\n");
            sb.Append("  Devicenum: ").Append(Devicenum).Append("\n");
            sb.Append("  Extinfo: ").Append(Extinfo).Append("\n");
            sb.Append("  Facetype: ").Append(Facetype).Append("\n");
            sb.Append("  Faceval: ").Append(Faceval).Append("\n");
            sb.Append("  Group: ").Append(Group).Append("\n");
            sb.Append("  Storecode: ").Append(Storecode).Append("\n");
            sb.Append("  Validtimes: ").Append(Validtimes).Append("\n");
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
            return this.Equals(input as ZolozAuthenticationCustomerFacemanageCreateModel);
        }

        /// <summary>
        /// Returns true if ZolozAuthenticationCustomerFacemanageCreateModel instances are equal
        /// </summary>
        /// <param name="input">Instance of ZolozAuthenticationCustomerFacemanageCreateModel to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(ZolozAuthenticationCustomerFacemanageCreateModel input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.Areacode == input.Areacode ||
                    (this.Areacode != null &&
                    this.Areacode.Equals(input.Areacode))
                ) && 
                (
                    this.BizType == input.BizType ||
                    (this.BizType != null &&
                    this.BizType.Equals(input.BizType))
                ) && 
                (
                    this.Bizscale == input.Bizscale ||
                    (this.Bizscale != null &&
                    this.Bizscale.Equals(input.Bizscale))
                ) && 
                (
                    this.Brandcode == input.Brandcode ||
                    (this.Brandcode != null &&
                    this.Brandcode.Equals(input.Brandcode))
                ) && 
                (
                    this.Devicenum == input.Devicenum ||
                    (this.Devicenum != null &&
                    this.Devicenum.Equals(input.Devicenum))
                ) && 
                (
                    this.Extinfo == input.Extinfo ||
                    (this.Extinfo != null &&
                    this.Extinfo.Equals(input.Extinfo))
                ) && 
                (
                    this.Facetype == input.Facetype ||
                    (this.Facetype != null &&
                    this.Facetype.Equals(input.Facetype))
                ) && 
                (
                    this.Faceval == input.Faceval ||
                    (this.Faceval != null &&
                    this.Faceval.Equals(input.Faceval))
                ) && 
                (
                    this.Group == input.Group ||
                    (this.Group != null &&
                    this.Group.Equals(input.Group))
                ) && 
                (
                    this.Storecode == input.Storecode ||
                    (this.Storecode != null &&
                    this.Storecode.Equals(input.Storecode))
                ) && 
                (
                    this.Validtimes == input.Validtimes ||
                    (this.Validtimes != null &&
                    this.Validtimes.Equals(input.Validtimes))
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
                if (this.Areacode != null)
                {
                    hashCode = (hashCode * 59) + this.Areacode.GetHashCode();
                }
                if (this.BizType != null)
                {
                    hashCode = (hashCode * 59) + this.BizType.GetHashCode();
                }
                if (this.Bizscale != null)
                {
                    hashCode = (hashCode * 59) + this.Bizscale.GetHashCode();
                }
                if (this.Brandcode != null)
                {
                    hashCode = (hashCode * 59) + this.Brandcode.GetHashCode();
                }
                if (this.Devicenum != null)
                {
                    hashCode = (hashCode * 59) + this.Devicenum.GetHashCode();
                }
                if (this.Extinfo != null)
                {
                    hashCode = (hashCode * 59) + this.Extinfo.GetHashCode();
                }
                if (this.Facetype != null)
                {
                    hashCode = (hashCode * 59) + this.Facetype.GetHashCode();
                }
                if (this.Faceval != null)
                {
                    hashCode = (hashCode * 59) + this.Faceval.GetHashCode();
                }
                if (this.Group != null)
                {
                    hashCode = (hashCode * 59) + this.Group.GetHashCode();
                }
                if (this.Storecode != null)
                {
                    hashCode = (hashCode * 59) + this.Storecode.GetHashCode();
                }
                if (this.Validtimes != null)
                {
                    hashCode = (hashCode * 59) + this.Validtimes.GetHashCode();
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
