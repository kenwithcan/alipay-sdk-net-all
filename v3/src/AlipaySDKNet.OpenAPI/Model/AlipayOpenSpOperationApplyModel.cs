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
    /// AlipayOpenSpOperationApplyModel
    /// </summary>
    [DataContract(Name = "AlipayOpenSpOperationApplyModel")]
    public partial class AlipayOpenSpOperationApplyModel : IEquatable<AlipayOpenSpOperationApplyModel>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayOpenSpOperationApplyModel" /> class.
        /// </summary>
        /// <param name="accessProductCode">接入的产品编号。 枚举如下： * OPENAPI_BIND_DEFAULT：操作类型为账号绑定。 * OPENAPI_AUTH_DEFAULT：操作类型为代运营授权时。.</param>
        /// <param name="alipayAccount">支付宝登录账号，通常为手机号或者邮箱。 间连场景必填。 直连场景选填，特别注意merchant_no和alipay_account不能同时为空，都有值优先取merchant_no。.</param>
        /// <param name="isvScenePermissions">场景授权列表结构结构：场景codeA:权限code1,权限code2;场景codeB:权限code1,权限code2; 说明： * 本参数和access_product_code只需要传一个。 * 场景 + 权限Code含义：    SHOP_MANAGE:SHOP_MANAGE_BASE：管理门店信息    MINI_APP_OPER:MINI_APP_OPER_BASE：运营支付宝小程序    PROMOTION_MANAGE:PROMOTION_MANAGE_BASE：运营营销活动    OPERATION_POINTS:OPERATION_POINTS_BASE：管理运营积分    INCENTIVE_POINT_MANAGE:INCENTIVE_POINT_MANAGE_BASE：管理激励点数.</param>
        /// <param name="merchantNo">支付宝商户号。 间连场景，merchant_no必填，传入商户smid，特别注意仅支持2088开头的间连商户。 直连场景，merchant_no选填，传入商户支付宝pid，特别注意merchant_no和alipay_account不能同时为空，优先取merchant_no。.</param>
        /// <param name="operateType">代运营操作类型。枚举如下： * ACCOUNT_BIND：代表绑定支付宝账号，仅对于间连商户。 * OPERATION_AUTH：代表代运营授权，支持间连和直连商户，其中间连场景包含绑定支付宝账号。.</param>
        /// <param name="outBizNo">外部操作流水，ISV自定义。每次操作需要确保唯一。.</param>
        public AlipayOpenSpOperationApplyModel(string accessProductCode = default(string), string alipayAccount = default(string), string isvScenePermissions = default(string), string merchantNo = default(string), string operateType = default(string), string outBizNo = default(string))
        {
            this.AccessProductCode = accessProductCode;
            this.AlipayAccount = alipayAccount;
            this.IsvScenePermissions = isvScenePermissions;
            this.MerchantNo = merchantNo;
            this.OperateType = operateType;
            this.OutBizNo = outBizNo;
        }

        /// <summary>
        /// 接入的产品编号。 枚举如下： * OPENAPI_BIND_DEFAULT：操作类型为账号绑定。 * OPENAPI_AUTH_DEFAULT：操作类型为代运营授权时。
        /// </summary>
        /// <value>接入的产品编号。 枚举如下： * OPENAPI_BIND_DEFAULT：操作类型为账号绑定。 * OPENAPI_AUTH_DEFAULT：操作类型为代运营授权时。</value>
        [DataMember(Name = "access_product_code", EmitDefaultValue = false)]
        public string AccessProductCode { get; set; }

        /// <summary>
        /// 支付宝登录账号，通常为手机号或者邮箱。 间连场景必填。 直连场景选填，特别注意merchant_no和alipay_account不能同时为空，都有值优先取merchant_no。
        /// </summary>
        /// <value>支付宝登录账号，通常为手机号或者邮箱。 间连场景必填。 直连场景选填，特别注意merchant_no和alipay_account不能同时为空，都有值优先取merchant_no。</value>
        [DataMember(Name = "alipay_account", EmitDefaultValue = false)]
        public string AlipayAccount { get; set; }

        /// <summary>
        /// 场景授权列表结构结构：场景codeA:权限code1,权限code2;场景codeB:权限code1,权限code2; 说明： * 本参数和access_product_code只需要传一个。 * 场景 + 权限Code含义：    SHOP_MANAGE:SHOP_MANAGE_BASE：管理门店信息    MINI_APP_OPER:MINI_APP_OPER_BASE：运营支付宝小程序    PROMOTION_MANAGE:PROMOTION_MANAGE_BASE：运营营销活动    OPERATION_POINTS:OPERATION_POINTS_BASE：管理运营积分    INCENTIVE_POINT_MANAGE:INCENTIVE_POINT_MANAGE_BASE：管理激励点数
        /// </summary>
        /// <value>场景授权列表结构结构：场景codeA:权限code1,权限code2;场景codeB:权限code1,权限code2; 说明： * 本参数和access_product_code只需要传一个。 * 场景 + 权限Code含义：    SHOP_MANAGE:SHOP_MANAGE_BASE：管理门店信息    MINI_APP_OPER:MINI_APP_OPER_BASE：运营支付宝小程序    PROMOTION_MANAGE:PROMOTION_MANAGE_BASE：运营营销活动    OPERATION_POINTS:OPERATION_POINTS_BASE：管理运营积分    INCENTIVE_POINT_MANAGE:INCENTIVE_POINT_MANAGE_BASE：管理激励点数</value>
        [DataMember(Name = "isv_scene_permissions", EmitDefaultValue = false)]
        public string IsvScenePermissions { get; set; }

        /// <summary>
        /// 支付宝商户号。 间连场景，merchant_no必填，传入商户smid，特别注意仅支持2088开头的间连商户。 直连场景，merchant_no选填，传入商户支付宝pid，特别注意merchant_no和alipay_account不能同时为空，优先取merchant_no。
        /// </summary>
        /// <value>支付宝商户号。 间连场景，merchant_no必填，传入商户smid，特别注意仅支持2088开头的间连商户。 直连场景，merchant_no选填，传入商户支付宝pid，特别注意merchant_no和alipay_account不能同时为空，优先取merchant_no。</value>
        [DataMember(Name = "merchant_no", EmitDefaultValue = false)]
        public string MerchantNo { get; set; }

        /// <summary>
        /// 代运营操作类型。枚举如下： * ACCOUNT_BIND：代表绑定支付宝账号，仅对于间连商户。 * OPERATION_AUTH：代表代运营授权，支持间连和直连商户，其中间连场景包含绑定支付宝账号。
        /// </summary>
        /// <value>代运营操作类型。枚举如下： * ACCOUNT_BIND：代表绑定支付宝账号，仅对于间连商户。 * OPERATION_AUTH：代表代运营授权，支持间连和直连商户，其中间连场景包含绑定支付宝账号。</value>
        [DataMember(Name = "operate_type", EmitDefaultValue = false)]
        public string OperateType { get; set; }

        /// <summary>
        /// 外部操作流水，ISV自定义。每次操作需要确保唯一。
        /// </summary>
        /// <value>外部操作流水，ISV自定义。每次操作需要确保唯一。</value>
        [DataMember(Name = "out_biz_no", EmitDefaultValue = false)]
        public string OutBizNo { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class AlipayOpenSpOperationApplyModel {\n");
            sb.Append("  AccessProductCode: ").Append(AccessProductCode).Append("\n");
            sb.Append("  AlipayAccount: ").Append(AlipayAccount).Append("\n");
            sb.Append("  IsvScenePermissions: ").Append(IsvScenePermissions).Append("\n");
            sb.Append("  MerchantNo: ").Append(MerchantNo).Append("\n");
            sb.Append("  OperateType: ").Append(OperateType).Append("\n");
            sb.Append("  OutBizNo: ").Append(OutBizNo).Append("\n");
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
            return this.Equals(input as AlipayOpenSpOperationApplyModel);
        }

        /// <summary>
        /// Returns true if AlipayOpenSpOperationApplyModel instances are equal
        /// </summary>
        /// <param name="input">Instance of AlipayOpenSpOperationApplyModel to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(AlipayOpenSpOperationApplyModel input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.AccessProductCode == input.AccessProductCode ||
                    (this.AccessProductCode != null &&
                    this.AccessProductCode.Equals(input.AccessProductCode))
                ) && 
                (
                    this.AlipayAccount == input.AlipayAccount ||
                    (this.AlipayAccount != null &&
                    this.AlipayAccount.Equals(input.AlipayAccount))
                ) && 
                (
                    this.IsvScenePermissions == input.IsvScenePermissions ||
                    (this.IsvScenePermissions != null &&
                    this.IsvScenePermissions.Equals(input.IsvScenePermissions))
                ) && 
                (
                    this.MerchantNo == input.MerchantNo ||
                    (this.MerchantNo != null &&
                    this.MerchantNo.Equals(input.MerchantNo))
                ) && 
                (
                    this.OperateType == input.OperateType ||
                    (this.OperateType != null &&
                    this.OperateType.Equals(input.OperateType))
                ) && 
                (
                    this.OutBizNo == input.OutBizNo ||
                    (this.OutBizNo != null &&
                    this.OutBizNo.Equals(input.OutBizNo))
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
                if (this.AccessProductCode != null)
                {
                    hashCode = (hashCode * 59) + this.AccessProductCode.GetHashCode();
                }
                if (this.AlipayAccount != null)
                {
                    hashCode = (hashCode * 59) + this.AlipayAccount.GetHashCode();
                }
                if (this.IsvScenePermissions != null)
                {
                    hashCode = (hashCode * 59) + this.IsvScenePermissions.GetHashCode();
                }
                if (this.MerchantNo != null)
                {
                    hashCode = (hashCode * 59) + this.MerchantNo.GetHashCode();
                }
                if (this.OperateType != null)
                {
                    hashCode = (hashCode * 59) + this.OperateType.GetHashCode();
                }
                if (this.OutBizNo != null)
                {
                    hashCode = (hashCode * 59) + this.OutBizNo.GetHashCode();
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
