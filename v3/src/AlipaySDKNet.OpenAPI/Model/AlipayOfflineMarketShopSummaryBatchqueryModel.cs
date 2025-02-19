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
    /// AlipayOfflineMarketShopSummaryBatchqueryModel
    /// </summary>
    [DataContract(Name = "AlipayOfflineMarketShopSummaryBatchqueryModel")]
    public partial class AlipayOfflineMarketShopSummaryBatchqueryModel : IEquatable<AlipayOfflineMarketShopSummaryBatchqueryModel>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayOfflineMarketShopSummaryBatchqueryModel" /> class.
        /// </summary>
        /// <param name="bizChannel">表示接口查询门店的业务渠道限制：ALL、 POS、不传。不传代表只查询普通门店，传入POS代表只查询简易门店，传入ALL代表查询普通门店和简易门店。.</param>
        /// <param name="brandName">品牌名.</param>
        /// <param name="cityCode">城市编码，国标码，如：120100表示天津市.</param>
        /// <param name="districtCode">区域编码，如：120104表示南开区.</param>
        /// <param name="opRole">表示接口业务的调用方身份：ISV、 服务商身份标识。传入ISV代表系统集成商身份。传入PROVIDER代表服务商。.</param>
        /// <param name="pageNo">页码，留空标示第一页，默认 20个结果为一页.</param>
        /// <param name="pageSize">每页记录数，默认20，最大 100.</param>
        /// <param name="provinceCode">省份编码，国标码，如：120000表示天津.</param>
        /// <param name="queryType">门店数据查询类型，根据类型可以返回指定的门店数据，目前支持的类型如下：  BRAND_RELATION ： 品牌商关联店铺  MALL_SELF ：MALL自己的门店  MALL_RELATION：MALL关联下的门店  MERCHANT_SELF:商户自己的门店  KB_PROMOTER：口碑客推广者.</param>
        /// <param name="relatedPartnerId">query_type查询类型下所关联的商户PID.</param>
        /// <param name="shopId">门店ID.</param>
        /// <param name="shopStatus">门店状态，传入多个状态，多个状态使用英文逗号隔开，例如：PAUSED,OPEN  店铺状态：OPEN（营业）、PAUSED（暂停）、INIT（初始）、FREEZE（冻结）、CLOSED（关店）.</param>
        public AlipayOfflineMarketShopSummaryBatchqueryModel(string bizChannel = default(string), string brandName = default(string), string cityCode = default(string), string districtCode = default(string), string opRole = default(string), int pageNo = default(int), int pageSize = default(int), string provinceCode = default(string), string queryType = default(string), string relatedPartnerId = default(string), string shopId = default(string), string shopStatus = default(string))
        {
            this.BizChannel = bizChannel;
            this.BrandName = brandName;
            this.CityCode = cityCode;
            this.DistrictCode = districtCode;
            this.OpRole = opRole;
            this.PageNo = pageNo;
            this.PageSize = pageSize;
            this.ProvinceCode = provinceCode;
            this.QueryType = queryType;
            this.RelatedPartnerId = relatedPartnerId;
            this.ShopId = shopId;
            this.ShopStatus = shopStatus;
        }

        /// <summary>
        /// 表示接口查询门店的业务渠道限制：ALL、 POS、不传。不传代表只查询普通门店，传入POS代表只查询简易门店，传入ALL代表查询普通门店和简易门店。
        /// </summary>
        /// <value>表示接口查询门店的业务渠道限制：ALL、 POS、不传。不传代表只查询普通门店，传入POS代表只查询简易门店，传入ALL代表查询普通门店和简易门店。</value>
        [DataMember(Name = "biz_channel", EmitDefaultValue = false)]
        public string BizChannel { get; set; }

        /// <summary>
        /// 品牌名
        /// </summary>
        /// <value>品牌名</value>
        [DataMember(Name = "brand_name", EmitDefaultValue = false)]
        public string BrandName { get; set; }

        /// <summary>
        /// 城市编码，国标码，如：120100表示天津市
        /// </summary>
        /// <value>城市编码，国标码，如：120100表示天津市</value>
        [DataMember(Name = "city_code", EmitDefaultValue = false)]
        public string CityCode { get; set; }

        /// <summary>
        /// 区域编码，如：120104表示南开区
        /// </summary>
        /// <value>区域编码，如：120104表示南开区</value>
        [DataMember(Name = "district_code", EmitDefaultValue = false)]
        public string DistrictCode { get; set; }

        /// <summary>
        /// 表示接口业务的调用方身份：ISV、 服务商身份标识。传入ISV代表系统集成商身份。传入PROVIDER代表服务商。
        /// </summary>
        /// <value>表示接口业务的调用方身份：ISV、 服务商身份标识。传入ISV代表系统集成商身份。传入PROVIDER代表服务商。</value>
        [DataMember(Name = "op_role", EmitDefaultValue = false)]
        public string OpRole { get; set; }

        /// <summary>
        /// 页码，留空标示第一页，默认 20个结果为一页
        /// </summary>
        /// <value>页码，留空标示第一页，默认 20个结果为一页</value>
        [DataMember(Name = "page_no", EmitDefaultValue = false)]
        public int PageNo { get; set; }

        /// <summary>
        /// 每页记录数，默认20，最大 100
        /// </summary>
        /// <value>每页记录数，默认20，最大 100</value>
        [DataMember(Name = "page_size", EmitDefaultValue = false)]
        public int PageSize { get; set; }

        /// <summary>
        /// 省份编码，国标码，如：120000表示天津
        /// </summary>
        /// <value>省份编码，国标码，如：120000表示天津</value>
        [DataMember(Name = "province_code", EmitDefaultValue = false)]
        public string ProvinceCode { get; set; }

        /// <summary>
        /// 门店数据查询类型，根据类型可以返回指定的门店数据，目前支持的类型如下：  BRAND_RELATION ： 品牌商关联店铺  MALL_SELF ：MALL自己的门店  MALL_RELATION：MALL关联下的门店  MERCHANT_SELF:商户自己的门店  KB_PROMOTER：口碑客推广者
        /// </summary>
        /// <value>门店数据查询类型，根据类型可以返回指定的门店数据，目前支持的类型如下：  BRAND_RELATION ： 品牌商关联店铺  MALL_SELF ：MALL自己的门店  MALL_RELATION：MALL关联下的门店  MERCHANT_SELF:商户自己的门店  KB_PROMOTER：口碑客推广者</value>
        [DataMember(Name = "query_type", EmitDefaultValue = false)]
        public string QueryType { get; set; }

        /// <summary>
        /// query_type查询类型下所关联的商户PID
        /// </summary>
        /// <value>query_type查询类型下所关联的商户PID</value>
        [DataMember(Name = "related_partner_id", EmitDefaultValue = false)]
        public string RelatedPartnerId { get; set; }

        /// <summary>
        /// 门店ID
        /// </summary>
        /// <value>门店ID</value>
        [DataMember(Name = "shop_id", EmitDefaultValue = false)]
        public string ShopId { get; set; }

        /// <summary>
        /// 门店状态，传入多个状态，多个状态使用英文逗号隔开，例如：PAUSED,OPEN  店铺状态：OPEN（营业）、PAUSED（暂停）、INIT（初始）、FREEZE（冻结）、CLOSED（关店）
        /// </summary>
        /// <value>门店状态，传入多个状态，多个状态使用英文逗号隔开，例如：PAUSED,OPEN  店铺状态：OPEN（营业）、PAUSED（暂停）、INIT（初始）、FREEZE（冻结）、CLOSED（关店）</value>
        [DataMember(Name = "shop_status", EmitDefaultValue = false)]
        public string ShopStatus { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class AlipayOfflineMarketShopSummaryBatchqueryModel {\n");
            sb.Append("  BizChannel: ").Append(BizChannel).Append("\n");
            sb.Append("  BrandName: ").Append(BrandName).Append("\n");
            sb.Append("  CityCode: ").Append(CityCode).Append("\n");
            sb.Append("  DistrictCode: ").Append(DistrictCode).Append("\n");
            sb.Append("  OpRole: ").Append(OpRole).Append("\n");
            sb.Append("  PageNo: ").Append(PageNo).Append("\n");
            sb.Append("  PageSize: ").Append(PageSize).Append("\n");
            sb.Append("  ProvinceCode: ").Append(ProvinceCode).Append("\n");
            sb.Append("  QueryType: ").Append(QueryType).Append("\n");
            sb.Append("  RelatedPartnerId: ").Append(RelatedPartnerId).Append("\n");
            sb.Append("  ShopId: ").Append(ShopId).Append("\n");
            sb.Append("  ShopStatus: ").Append(ShopStatus).Append("\n");
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
            return this.Equals(input as AlipayOfflineMarketShopSummaryBatchqueryModel);
        }

        /// <summary>
        /// Returns true if AlipayOfflineMarketShopSummaryBatchqueryModel instances are equal
        /// </summary>
        /// <param name="input">Instance of AlipayOfflineMarketShopSummaryBatchqueryModel to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(AlipayOfflineMarketShopSummaryBatchqueryModel input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.BizChannel == input.BizChannel ||
                    (this.BizChannel != null &&
                    this.BizChannel.Equals(input.BizChannel))
                ) && 
                (
                    this.BrandName == input.BrandName ||
                    (this.BrandName != null &&
                    this.BrandName.Equals(input.BrandName))
                ) && 
                (
                    this.CityCode == input.CityCode ||
                    (this.CityCode != null &&
                    this.CityCode.Equals(input.CityCode))
                ) && 
                (
                    this.DistrictCode == input.DistrictCode ||
                    (this.DistrictCode != null &&
                    this.DistrictCode.Equals(input.DistrictCode))
                ) && 
                (
                    this.OpRole == input.OpRole ||
                    (this.OpRole != null &&
                    this.OpRole.Equals(input.OpRole))
                ) && 
                (
                    this.PageNo == input.PageNo ||
                    this.PageNo.Equals(input.PageNo)
                ) && 
                (
                    this.PageSize == input.PageSize ||
                    this.PageSize.Equals(input.PageSize)
                ) && 
                (
                    this.ProvinceCode == input.ProvinceCode ||
                    (this.ProvinceCode != null &&
                    this.ProvinceCode.Equals(input.ProvinceCode))
                ) && 
                (
                    this.QueryType == input.QueryType ||
                    (this.QueryType != null &&
                    this.QueryType.Equals(input.QueryType))
                ) && 
                (
                    this.RelatedPartnerId == input.RelatedPartnerId ||
                    (this.RelatedPartnerId != null &&
                    this.RelatedPartnerId.Equals(input.RelatedPartnerId))
                ) && 
                (
                    this.ShopId == input.ShopId ||
                    (this.ShopId != null &&
                    this.ShopId.Equals(input.ShopId))
                ) && 
                (
                    this.ShopStatus == input.ShopStatus ||
                    (this.ShopStatus != null &&
                    this.ShopStatus.Equals(input.ShopStatus))
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
                if (this.BizChannel != null)
                {
                    hashCode = (hashCode * 59) + this.BizChannel.GetHashCode();
                }
                if (this.BrandName != null)
                {
                    hashCode = (hashCode * 59) + this.BrandName.GetHashCode();
                }
                if (this.CityCode != null)
                {
                    hashCode = (hashCode * 59) + this.CityCode.GetHashCode();
                }
                if (this.DistrictCode != null)
                {
                    hashCode = (hashCode * 59) + this.DistrictCode.GetHashCode();
                }
                if (this.OpRole != null)
                {
                    hashCode = (hashCode * 59) + this.OpRole.GetHashCode();
                }
                hashCode = (hashCode * 59) + this.PageNo.GetHashCode();
                hashCode = (hashCode * 59) + this.PageSize.GetHashCode();
                if (this.ProvinceCode != null)
                {
                    hashCode = (hashCode * 59) + this.ProvinceCode.GetHashCode();
                }
                if (this.QueryType != null)
                {
                    hashCode = (hashCode * 59) + this.QueryType.GetHashCode();
                }
                if (this.RelatedPartnerId != null)
                {
                    hashCode = (hashCode * 59) + this.RelatedPartnerId.GetHashCode();
                }
                if (this.ShopId != null)
                {
                    hashCode = (hashCode * 59) + this.ShopId.GetHashCode();
                }
                if (this.ShopStatus != null)
                {
                    hashCode = (hashCode * 59) + this.ShopStatus.GetHashCode();
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
